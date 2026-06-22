"""
CyberJobs Aggregator — pulls live entry-level cybersecurity & IT roles
from public Greenhouse job-board APIs, filters/categorizes them, and
outputs HTML, CSV, and Markdown. Demo build.
"""
import json, csv, urllib.request, datetime, html, re, os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Companies with public Greenhouse boards (free, structured JSON API) ---
# Greenhouse public endpoint: https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true
COMPANIES = {
    # --- Pure cybersecurity vendors ---
    "Okta": "okta",
    "Zscaler": "zscaler",
    "Wiz": "wizinc",
    "Tenable": "tenableinc",
    "Recorded Future": "recordedfuture",
    "Tanium": "tanium",
    "Abnormal Security": "abnormalsecurity",
    "Axonius": "axonius",
    "Netskope": "netskope",
    "Obsidian Security": "obsidiansecurity",
    "Armis": "armissecurity",
    "Dragos": "dragos",
    "Corelight": "corelight",
    "Nozomi Networks": "nozominetworks",
    "ThreatLocker": "threatlocker",
    "Huntress": "huntress",
    "Expel": "expel",
    "RunZero": "runzero",
    "Torq": "torq",
    "Cybereason": "cybereason",
    "Cymulate": "cymulate",
    "Apiiro": "apiiro",
    "Orca Security": "orcasecurity",
    "BeyondTrust": "beyondtrust",
    "Ping Identity": "pingidentity",
    "Keeper Security": "keepersecurity",
    "Bitwarden": "bitwarden",
    "Veracode": "veracode",
    "Bishop Fox": "bishopfox",
    "GuidePoint Security": "guidepointsecurity",
    "Cyware": "cyware",
    # --- Security-adjacent / identity / cloud security ---
    "Rubrik": "rubrik",
    "Elastic": "elastic",
    "Sumo Logic": "sumologic",
    "Verkada": "verkada",
    "Samsara": "samsara",
    "Veriff": "veriff",
    "Jumio": "jumio",
    "Trace3": "trace3",
    # --- Big tech with large security teams ---
    "Stripe": "stripe",
    "Twilio": "twilio",
    "Databricks": "databricks",
    "Cloudflare": "cloudflare",
    "Coinbase": "coinbase",
    "Datadog": "datadog",
    "Robinhood": "robinhood",
    "Affirm": "affirm",
    "Dropbox": "dropbox",
    "Reddit": "reddit",
}

# --- Keyword rules for filtering + categorizing ---
CYBER_KW = ["security", "cyber", "soc ", "infosec", "threat", "vulnerability",
            "incident response", "appsec", "siem", "detection", "malware",
            "penetration", "red team", "blue team", "security analyst",
            "security engineer", "trust and safety", "cryptograph"]
IT_KW = ["help desk", "helpdesk", "service desk", "desktop support",
         "it support", "system administrator", "sysadmin", "noc ",
         "network technician", "it technician", "technical support",
         "it operations", "support engineer", "support specialist"]
ENTRY_KW = ["intern", "new grad", "new-grad", "graduate", "entry", "junior",
            "associate", "i ", " i", "early career", "university", "apprentice",
            "level 1", "tier 1", "trainee"]
SENIOR_BLOCK = ["senior", "staff", "principal", "lead", "manager", "director",
                "head of", "vp ", "ii", "iii", "iv", " 2", " 3", "sr."]

def fetch(token):
    url = f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"  ! could not fetch {token}: {e}")
        return None

def categorize(title):
    t = title.lower()
    if any(k in t for k in CYBER_KW):
        return "Cybersecurity"
    if any(k in t for k in IT_KW):
        return "IT / On-Ramp"
    return None

def is_entry(title):
    t = title.lower()
    # entry signal present AND no obvious senior signal
    has_entry = any(k in t for k in ENTRY_KW)
    has_senior = any(k in t for k in SENIOR_BLOCK)
    return has_entry and not has_senior

def clean_loc(job):
    loc = job.get("location", {})
    return (loc.get("name") if isinstance(loc, dict) else str(loc)) or "—"

results = []
print("Fetching live job boards...\n")
for name, token in COMPANIES.items():
    print(f"- {name}...", end=" ")
    data = fetch(token)
    if not data:
        continue
    jobs = data.get("jobs", [])
    count = 0
    for j in jobs:
        title = j.get("title", "")
        cat = categorize(title)
        if not cat:
            continue
        # keep entry-level OR keep all cyber (cyber entry roles are rare, cast wider)
        entry = is_entry(title)
        results.append({
            "company": name,
            "title": title.strip(),
            "category": cat,
            "entry_level": "Yes" if entry else "Maybe",
            "location": clean_loc(j),
            "url": j.get("absolute_url", ""),
            "updated": (j.get("updated_at","") or "")[:10],
        })
        count += 1
    print(f"{count} matched")

# Sort: cyber first, then entry-level first, then company
results.sort(key=lambda r: (r["category"] != "Cybersecurity",
                            r["entry_level"] != "Yes",
                            r["company"]))

print(f"\nTOTAL matched roles: {len(results)}")
cyber = sum(1 for r in results if r['category']=='Cybersecurity')
it = sum(1 for r in results if r['category']=='IT / On-Ramp')
print(f"  Cybersecurity: {cyber}   IT/On-Ramp: {it}")

# ---------- CSV ----------
with open(os.path.join(OUT_DIR, "cyber_jobs.csv"),"w",newline="",encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["company","title","category","entry_level","location","updated","url"])
    w.writeheader()
    for r in results: w.writerow(r)

# ---------- Markdown ----------
with open(os.path.join(OUT_DIR, "cyber_jobs.md"),"w",encoding="utf-8") as f:
    f.write(f"# Cybersecurity & IT Job Tracker\n\n")
    f.write(f"_Auto-generated {datetime.date.today()} — {len(results)} roles from {len(COMPANIES)} company boards_\n\n")
    f.write("| Company | Role | Category | Entry? | Location | Apply |\n")
    f.write("|---|---|---|---|---|---|\n")
    for r in results:
        f.write(f"| {r['company']} | {r['title']} | {r['category']} | {r['entry_level']} | {r['location']} | [Apply]({r['url']}) |\n")

# ---------- HTML ----------
rows_html = ""
for r in results:
    badge = "#2E75B6" if r["category"]=="Cybersecurity" else "#70AD47"
    entry_badge = "#1F7A1F" if r["entry_level"]=="Yes" else "#B8860B"
    rows_html += f"""<tr data-cat="{r['category']}" data-entry="{r['entry_level']}">
      <td><b>{html.escape(r['company'])}</b></td>
      <td>{html.escape(r['title'])}</td>
      <td><span style="background:{badge};color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;">{r['category']}</span></td>
      <td><span style="color:{entry_badge};font-weight:600;">{r['entry_level']}</span></td>
      <td>{html.escape(r['location'])}</td>
      <td>{r['updated']}</td>
      <td><a href="{r['url']}" target="_blank">Apply →</a></td>
    </tr>"""

html_doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Cyber & IT Job Tracker</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#1a1a1a;background:#fafafa;}}
h1{{color:#1F4E79;margin-bottom:4px;}}
.sub{{color:#666;margin-bottom:18px;}}
.controls{{margin-bottom:16px;}}
button{{background:#1F4E79;color:#fff;border:0;padding:8px 14px;border-radius:6px;margin-right:8px;cursor:pointer;font-size:14px;}}
button.alt{{background:#888;}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.1);}}
th{{background:#1F4E79;color:#fff;text-align:left;padding:10px;font-size:13px;}}
td{{padding:9px 10px;border-bottom:1px solid #eee;font-size:13px;}}
tr:hover{{background:#f0f6ff;}}
a{{color:#1F4E79;font-weight:600;text-decoration:none;}}
</style></head><body>
<h1>Cybersecurity &amp; IT Job Tracker</h1>
<div class="sub">Auto-generated {datetime.date.today()} · {len(results)} roles from {len(COMPANIES)} live company boards · {cyber} cyber / {it} IT</div>
<div class="controls">
  <button onclick="filt('all')">All</button>
  <button onclick="filt('Cybersecurity')">Cybersecurity</button>
  <button onclick="filt('IT / On-Ramp')">IT / On-Ramp</button>
  <button class="alt" onclick="entryOnly()">Entry-Level Only</button>
  <button class="alt" onclick="filt('all')">Reset</button>
</div>
<table id="t">
<thead><tr><th>Company</th><th>Role</th><th>Category</th><th>Entry?</th><th>Location</th><th>Updated</th><th>Link</th></tr></thead>
<tbody>{rows_html}</tbody></table>
<script>
function filt(c){{document.querySelectorAll('#t tbody tr').forEach(r=>{{
  r.style.display = (c==='all'||r.dataset.cat===c)?'':'none';}});}}
function entryOnly(){{document.querySelectorAll('#t tbody tr').forEach(r=>{{
  r.style.display = (r.dataset.entry==='Yes')?'':'none';}});}}
</script>
</body></html>"""
with open(os.path.join(OUT_DIR, "cyber_jobs.html"),"w",encoding="utf-8") as f:
    f.write(html_doc)

print("\nGenerated: cyber_jobs.html, cyber_jobs.csv, cyber_jobs.md")
