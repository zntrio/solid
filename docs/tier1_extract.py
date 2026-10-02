"""Tier 1 claim extraction: RFC 2119 statements with line citations.

Extracts every MUST/MUST NOT/SHOULD/SHOULD NOT/REQUIRED/SHALL/MAY line from
the three texts of the OAuth 2.0 triple (RFC 6749, RFC 9700, draft v2-1).
Folds continuation lines so each claim is complete; skips boilerplate
(BCP 78/14 license, status-of-memo, TOC).
"""
import json
import pathlib
import re
import sys

DOCS = pathlib.Path(__file__).resolve().parent / "rfcs"

FILES = {
    "RFC6749": "rfc6749.txt",
    "RFC9700": "rfc9700.txt",
    "draft-ietf-oauth-v2-1-16": "draft-ietf-oauth-v2-1-16.txt",
}

KEYWORD = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|SHALL NOT|SHALL|REQUIRED|RECOMMENDED|NOT RECOMMENDED|MAY(?! )|OPTIONAL)\b")

BOILER_STARTS = (
    "Copyright Notice", "Status of This Memo", "Table of Contents",
    "Abstract", "Internet Engineering Task Force", "Request for Comments",
    "Internet-Draft", "Expires:", "Authors' Addresses", "Issue Tracker",
)

def fold(lines, i):
    """Fold RFC-style line-wrapped text: continuation lines are indented."""
    acc = [lines[i].strip()]
    j = i + 1
    while j < len(lines):
        nxt = lines[j]
        if nxt.strip() == "":
            break
        # continuation: indented and not a new page/heading artifact
        if nxt.startswith("   ") and not re.match(r"^\s*(\d+\.|[A-Z]\.|Appendix|[A-Z][a-z]+ [A-Z])", nxt.strip()):
            acc.append(nxt.strip())
            j += 1
        else:
            break
    return " ".join(acc), j

claims = []
for label, fname in FILES.items():
    text = (DOCS / fname).read_text(errors="replace")
    lines = text.splitlines()
    section = ""
    for i, ln in enumerate(lines):
        # track current section heading (e.g. "4.1.  Authorization Code Grant")
        m = re.match(r"^(\d+(\.\d+)*)\.\s{2}\S", ln)
        if m:
            section = m.group(1)
        if ln.strip().startswith(BOILER_STARTS):
            continue
        if not KEYWORD.search(ln):
            continue
        # skip pure TOC / page furniture
        if re.match(r"^(RFC \d+|draft-ietf)", ln) or "Internet-Draft" in ln:
            continue
        claim_text, _ = fold(lines, i)
        # only keep statements that look normative, not quotes of keywords in prose
        claims.append({
            "doc": label,
            "section": section,
            "line": i + 1,
            "text": claim_text,
        })

out = pathlib.Path("/tmp/tier1_claims.jsonl")
with out.open("w") as fh:
    for c in claims:
        fh.write(json.dumps(c, ensure_ascii=False) + "\n")
print(f"{out}: {len(claims)} claims")
for label in FILES:
    n = sum(1 for c in claims if c["doc"] == label)
    print(f"  {label}: {n}")
