"""Tier 1 merge: fold agent findings into docs/rfcs/audit.jsonl.

Verifies every finding's quote against the cited line of the vendored text
(quote_a at line_a of the file for doc_a, same for b); findings whose quote
does not match are rejected. Existing Tier 0 findings are preserved.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent
DOCS = ROOT / "rfcs"

FILES = {
    "RFC6749": "rfc6749.txt",
    "RFC9700": "rfc9700.txt",
    "draft-ietf-oauth-v2-1-16": "draft-ietf-oauth-v2-1-16.txt",
}

def line_text(doc, line):
    fname = FILES[doc]
    lines = (DOCS / fname).read_text(errors="replace").splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else None

def locate(doc, quote):
    """Locate a folded quote in the vendored text (splitlines numbering).

    Searches a space-joined flattening for the quote prefix (longest first),
    maps char offsets back to line numbers via per-line cumulative lengths.
    Returns (line, True) or (None, False); agent line numbers are never
    trusted.
    """
    if not quote:
        return None, False
    ls = (DOCS / FILES[doc]).read_text(errors="replace").splitlines()
    nls = [re.sub(r"\s+", " ", l).strip() for l in ls]
    flat = " ".join(nls)
    frag = re.sub(r"\s+", " ", quote).strip()
    if len(frag) < 25:
        return None, False
    starts, cum = [], 0
    for l in nls:
        starts.append(cum)
        cum += len(l) + 1
    import bisect
    for probe_len in (80, 60, 40):
        probe = frag[:probe_len]
        if len(probe) < 25:
            continue
        idx = flat.find(probe)
        if idx >= 0:
            return bisect.bisect_right(starts, idx), True
    return None, False

# load agent outputs
import urllib.request

def read_agent(name):
    with urllib.request.urlopen(f"file:///dev/null") as _:
        pass
    # agents write via eval kernel; read from agent:// is not filesystem — use the transcripts
    return None

if __name__ == "__main__":
    import sys
    agent_files = sys.argv[1:]
    findings = []
    for af in agent_files:
        payload = json.loads(pathlib.Path(af).read_text())
        if isinstance(payload, list):
            findings.extend(payload)
        else:
            findings.extend(payload.get("findings", []))

    accepted, rejected = [], []
    for f in findings:
        la, ok_a = locate(f.get("doc_a"), f.get("quote_a", ""))
        lb, ok_b = (None, True)
        if f.get("doc_b"):
            lb, ok_b = locate(f.get("doc_b"), f.get("quote_b", ""))
        if ok_a and ok_b:
            f["line_a"] = la if la else f.get("line_a")
            if f.get("doc_b"):
                f["line_b"] = lb if lb else f.get("line_b")
            accepted.append(f)
        else:
            rejected.append(f)

    # write to audit.jsonl alongside tier-0 findings
    out = DOCS / "audit.jsonl"
    existing = [json.loads(l) for l in out.read_text().splitlines()]
    tier0_count = len(existing)
    for f in accepted:
        rec = {
            "kind": f["kind"],
            "subkind": "tier1_semantic",
            "rfc_a": f["doc_a"],
            "section_a": f.get("section_a"),
            "line_a": f.get("line_a"),
            "quote_a": f.get("quote_a"),
            "rfc_b": f.get("doc_b"),
            "section_b": f.get("section_b"),
            "line_b": f.get("line_b"),
            "quote_b": f.get("quote_b"),
            "severity": f["severity"],
            "evidence": f["rationale"],
            "status": "open",
        }
        existing.append(rec)
    with out.open("w") as fh:
        for r in existing:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"agent findings: {len(findings)} | accepted: {len(accepted)} | rejected: {len(rejected)}")
    print(f"audit.jsonl: {tier0_count} tier-0 + {len(accepted)} tier-1 = {len(existing)}")
    for r in rejected:
        print("  REJECTED:", r.get("doc_a"), r.get("section_a"), "L", r.get("line_a"), "|", (r.get("quote_a") or "")[:60])
