import hashlib, json, re, pathlib, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" / "rfcs"

def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()

records = []
for f in sorted(DOCS.glob("*.txt")):
    name = f.name
    raw = f.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    rec = {
        "file": name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

    if m := re.match(r"rfc(\d+)\.txt$", name):
        num = m.group(1)
        rec["type"] = "rfc"
        rec["number"] = int(num)
        rec["source"] = f"https://www.rfc-editor.org/rfc/{name}"
        meta = json.loads(get(f"https://www.rfc-editor.org/rfc/rfc{num}.json"))
        rec["title"] = meta["title"]
        rec["authors"] = list(meta["authors"])
        rec["date"] = meta["pub_date"]
        rec["status"] = meta["status"]
        if o := meta.get("obsoletes"): rec["obsoletes"] = o
        if u := meta.get("updates"): rec["updates"] = u
        if oib := meta.get("obsoleted_by"): rec["obsoleted_by"] = oib
        if uib := meta.get("updated_by"): rec["updated_by"] = uib
        rec["doi"] = meta.get("doi")
    elif name.startswith("draft-"):
        dname = name[:-4]
        rec["type"] = "draft"
        rec["name"] = dname
        rec["revision"] = int(re.search(r"-(\d+)$", dname).group(1))
        rec["source"] = f"https://www.ietf.org/archive/id/{name}"
        # datatracker: latest revision metadata
        doc = json.loads(get(f"https://datatracker.ietf.org/api/v1/doc/document/{dname.rsplit('-', 1)[0]}/?format=json"))
        rec["title"] = doc.get("title")
        rec["latest_revision"] = int(doc["rev"])
        rec["current"] = (rec["revision"] == int(doc["rev"]))
        rec["date"] = doc["time"][:10]
        rec["expires"] = doc["expires"][:10]
        if doc.get("rfc_number"): rec["published_as_rfc"] = doc["rfc_number"]
        if doc.get("stream"):
            rec["stream"] = doc["stream"].rstrip("/").split("/")[-1]
        # authors via documentauthor
        base = dname.rsplit('-', 1)[0]
        au = json.loads(get(f"https://datatracker.ietf.org/api/v1/doc/documentauthor/?format=json&document__name={base}"))
        rec["authors"] = [json.loads(get("https://datatracker.ietf.org" + o["person"] + "?format=json"))["name"]
                          for o in sorted(au["objects"], key=lambda x: x["order"])]
    elif name == "openid-financial-api-jarm-ID1.txt":
        rec.update({
            "type": "openid",
            "title": "Financial-grade API: JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)",
            "status": "Draft-02",
            "date": "2018-10-17",
            "authors": ["T. Lodderstedt", "B. Campbell"],
            "source": "https://openid.net/specs/openid-financial-api-jarm.html",
            "note": "content is Draft-02 saved as HTML despite .txt extension; no plain-text source exists",
        })
    elif name == "openid-client-initiated-backchannel-authentication-core-1_0.txt":
        rec.update({
            "type": "openid",
            "title": "OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0",
            "status": "Final",
            "date": "2021-09-01",
            "authors": ["G. Fernandez", "F. Walter", "A. Nennker", "D. Tonge", "B. Campbell"],
            "source": f"https://openid.net/specs/{name}",
        })

    try:
        rec["synced"] = (get(rec["source"]) == raw)
    except Exception as e:
        rec["synced"] = None
        rec["sync_error"] = str(e)[:120]

    # key order: file, type, then rest
    ordered = {"file": rec.pop("file"), "type": rec.pop("type"), **rec}
    records.append(ordered)

out = DOCS / "index.jsonl"
with out.open("w") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"wrote {out} with {len(records)} records")
