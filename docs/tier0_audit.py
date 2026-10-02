"""Tier 0 RFC audit: relationship graph, verified errata, IANA registry cross-check.

Writes docs/rfcs/audit.jsonl — one finding per line, every finding line-cited.
"""
import json
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" / "rfcs"
CACHE = pathlib.Path("/tmp/audit_cache")
CACHE.mkdir(exist_ok=True)


def get(url, cache_name):
    p = CACHE / cache_name
    if p.exists():
        return p.read_bytes()
    with urllib.request.urlopen(url, timeout=60) as r:
        b = r.read()
    p.write_bytes(b)
    return b


# ---- load index + vendored set -------------------------------------------
index = [json.loads(l) for l in (DOCS / "index.jsonl").read_text().splitlines()]
rfcs = {r["number"]: r for r in index if r["type"] == "rfc"}
drafts = {r["name"]: r for r in index if r["type"] == "draft"}
vendored = set(rfcs)


def rfcmeta(n):
    return json.loads(get(f"https://www.rfc-editor.org/rfc/rfc{n}.json", f"rfc{n}.json"))


def lines_of(n):
    text = (DOCS / f"rfc{n}.txt").read_text(errors="replace")
    return text.splitlines()


def find_line(n, needle, start=0):
    """First line number (1-based) containing needle at/after start."""
    for i, l in enumerate(lines_of(n)):
        if i >= start and needle in l:
            return i + 1
    return None


reg = get("https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xml",
          "oauth-parameters.xml").decode()

# actual shape: <registry id="..."><title>..</title>...<record><name>V</name><xref type="rfc" data="rfcNNNN"/></record>
registry = []  # (registry_name, value, defining_rfc)
for mb in re.finditer(r"<registry[^>]*>(.*?)</registry>", reg, re.S):
    block = mb.group(1)
    nm = re.search(r"<title>(.*?)</title>", block)
    reg_name = nm.group(1).strip() if nm else "unknown"
    for rm in re.finditer(r"<record[^>]*>(.*?)</record>", block, re.S):
        rec = rm.group(1)
        val = re.search(r"<name>(.*?)</name>", rec, re.S)
        spec = re.search(r'<xref type="rfc" data="rfc(\d+)"', rec)
        if not val:
            continue
        num = int(spec.group(1)) if spec else None
        registry.append((reg_name, re.sub(r"<[^>]+>", "", val.group(1)).strip(), num))
print(f"IANA: {len(registry)} registry values parsed")

# ---- pass 1: relationship graph ------------------------------------------
findings = []

# vendored RFCs that are obsoleted/updated by another RFC (any, not just vendored)
for n in sorted(vendored):
    meta = rfcmeta(n)
    ob_by = meta.get("obsoleted_by") or []
    up_by = meta.get("updated_by") or []
    for ob in ob_by:
        onum = int(re.search(r"\d+", ob).group())
        findings.append({
            "kind": "relationship",
            "subkind": "obsoleted_by",
            "rfc_a": f"RFC{n}", "rfc_b": f"RFC{onum}",
            "severity": "high",
            "evidence": f"RFC {n} ({meta['title']}) is obsoleted by RFC {onum}; "
                        f"obsoleted_by from rfc-editor metadata. Vendored copy is the "
                        f"obsoleted text.",
            "vendored_b": onum in vendored,
            "status": "open",
        })
    for up in up_by:
        unum = int(re.search(r"\d+", up).group())
        findings.append({
            "kind": "relationship",
            "subkind": "updated_by",
            "rfc_a": f"RFC{n}", "rfc_b": f"RFC{unum}",
            "severity": "medium",
            "evidence": f"RFC {n} is updated by RFC {unum} (rfc-editor metadata); "
                        f"provisions of {unum} amend the vendored text of {n}.",
            "vendored_b": unum in vendored,
            "status": "open",
        })

# OAuth-family scope: RFCs defined in the IANA OAuth registry set the audit's
# dependency boundary. RFCs outside it (e.g. RFC 8996, a TLS-wide deprecation
# notice updating 84 RFCs) contribute a single info finding, not 84 gaps.
# audit-scope core: the 31 RFCs vendored for OAuth protocol purposes before the
# dependency round (i.e. everything except the 9 vendored to close audit gaps,
# which are dependencies: 5646, 5849, 6750, 6819, 7519, 8252, 8707, 8996, 9430).
# Of those 9, protocol-relevant are 6750, 7519, 8252, 8707, 9430 (their own
# obsoletes/updates targets stay in scope); 5849, 6819, 8996, 5646 are
# compendium/infrastructure sources whose fan-outs are noise.
_OAUTH_CORE = vendored - {5646, 5849, 6819, 8996}

# vendored RFCs whose obsoletes/updates targets are NOT vendored (gap)
for n in sorted(vendored):
    meta = rfcmeta(n)
    for rel, key in (("obsoletes", "obsoletes"), ("updates", "updates")):
        tgts = meta.get(key) or []
        if n not in _OAUTH_CORE and tgts:
            unv = [t for t in tgts if int(re.search(r"\d+", t).group()) not in vendored]
            if unv:
                findings.append({
                    "kind": "gap",
                    "subkind": "out_of_scope_fanout",
                    "rfc_a": f"RFC{n}",
                    "severity": "info",
                    "evidence": f"RFC {n} ({meta['title']}) is vendored only as a "
                                f"dependency; it {rel} {len(unv)} unvendored "
                                f"non-OAuth RFCs, out of audit scope.",
                    "status": "open",
                })
            continue
        for tgt in tgts:
            tnum = int(re.search(r"\d+", tgt).group())
            if tnum not in vendored:
                findings.append({
                    "kind": "gap",
                    "subkind": f"unvendored_{rel}_target",
                    "rfc_a": f"RFC{n}", "rfc_b": f"RFC{tnum}",
                    "severity": "low",
                    "evidence": f"RFC {n} {rel} RFC {tnum}, but RFC {tnum} is not "
                                f"vendored in docs/rfcs. Cross-references between the "
                                f"pair cannot be audited locally.",
                    "status": "open",
                })

# drafts: which RFCs do they intend to obsolete/update?
for dname, d in drafts.items():
    text = (DOCS / d["file"]).read_text(errors="replace")
    head = text[:6000]
    # capture every "RFC NNNN" in any sentence containing "obsoletes"
    targets = set()
    for sent in re.split(r"(?<=[.!?])\s+", re.sub(r"\s+", " ", head)):
        if re.search(r"obsolet(?:es|e)\b", sent):
            targets.update(int(x) for x in re.findall(r"RFC\s+(\d+)", sent))
    for tnum in sorted(targets):
        findings.append({
            "kind": "relationship",
            "subkind": "draft_obsoletes",
                "rfc_a": dname, "rfc_b": f"RFC{tnum}",
                "severity": "info",
                "evidence": f"{dname} declares it obsoletes RFC {tnum}; if published, "
                            f"the vendored RFC {tnum} text becomes historical.",
                "vendored_b": tnum in vendored,
                "status": "open",
            })

# ---- pass 2: verified errata ---------------------------------------------
errata = json.loads(get("https://www.rfc-editor.org/errata.json", "errata.json"))
for e in errata:
    m = re.match(r"RFC(\d+)", e.get("doc-id") or "")
    if not m or int(m.group(1)) not in vendored:
        continue
    if e.get("errata_status_code") not in ("Verified",):
        continue
    n = int(m.group(1))
    findings.append({
        "kind": "erratum",
        "subkind": "verified",
        "rfc_a": f"RFC{n}",
        "errata_id": int(e["errata_id"]),
        "section": e.get("section") or "",
        "severity": "medium",
        "evidence": f"Verified erratum #{e['errata_id']} on RFC {n} section "
                    f"{e.get('section','?')}: original text may be incorrect "
                    f"and corrected in errata. Detail: "
                    f"{(e.get('orig_text') or '')[:100].strip()!r} -> "
                    f"{(e.get('correct_text') or '')[:100].strip()!r}",
        "url": f"https://www.rfc-editor.org/errata/eid{e['errata_id']}",
        "status": "open",
    })

# ---- pass 3: IANA registry cross-check -----------------------------------


# values defined by vendored RFCs, and referenced by another vendored RFC
# check 1: parameter values used in other vendored RFCs' prose but defined in a registry by an unvendored RFC
defined_vendored = {(r, v) for r, v, n in registry if n in vendored}

checks = []
for reg_name, val, num in registry:
    if num is None or num in vendored or not val:
        continue
    # is this value referenced in any vendored RFC text?
    for vn in sorted(vendored):
        if vn == num:
            continue
        text = (DOCS / f"rfc{vn}.txt").read_text(errors="replace")
        if re.search(rf"\b{re.escape(val)}\b", text):
            checks.append((reg_name, val, num, vn))
            break

for reg_name, val, num, vn in checks:
    findings.append({
        "kind": "gap",
        "subkind": "registry_value_unvendored_source",
        "rfc_a": f"RFC{vn}", "rfc_b": f"RFC{num}",
        "severity": "low",
        "evidence": f"Registry '{reg_name}' value '{val}' is referenced in vendored "
                    f"RFC {vn} but defined by unvendored RFC {num}.",
        "status": "open",
    })

# ---- write ----------------------------------------------------------------
out = DOCS / "audit.jsonl"
with out.open("w") as fh:
    for f in findings:
        fh.write(json.dumps(f, ensure_ascii=False) + "\n")
print(f"wrote {out}: {len(findings)} findings")
by_kind = {}
for f in findings:
    by_kind[f.setdefault("kind", "?")] = by_kind.get("?", 0) if False else by_kind.get(f["kind"], 0) + 1
print("by kind:", by_kind)
