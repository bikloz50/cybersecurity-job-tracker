"""
CyberJobs Aggregator — pulls live entry-level cybersecurity & IT roles
from public Greenhouse job-board APIs, filters/categorizes them, and
outputs HTML, CSV, and Markdown. Demo build.
"""
import json, csv, urllib.request, datetime, html, re, os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- US state names and abbreviations ---
US_STATES = {
    "alabama","alaska","arizona","arkansas","california","colorado","connecticut",
    "delaware","florida","georgia","hawaii","idaho","illinois","indiana","iowa",
    "kansas","kentucky","louisiana","maine","maryland","massachusetts","michigan",
    "minnesota","mississippi","missouri","montana","nebraska","nevada",
    "new hampshire","new jersey","new mexico","new york","north carolina",
    "north dakota","ohio","oklahoma","oregon","pennsylvania","rhode island",
    "south carolina","south dakota","tennessee","texas","utah","vermont",
    "virginia","washington","west virginia","wisconsin","wyoming",
    "district of columbia","washington dc","washington d.c.",
    # abbreviations
    "al","ak","az","ar","ca","co","ct","de","fl","ga","hi","id","il","in",
    "ia","ks","ky","la","me","md","ma","mi","mn","ms","mo","mt","ne","nv",
    "nh","nj","nm","ny","nc","nd","oh","ok","or","pa","ri","sc","sd","tn",
    "tx","ut","vt","va","wa","wv","wi","wy","dc",
}

FOREIGN_SIGNALS = [
    "uk","united kingdom","england","scotland","ireland","netherlands","germany",
    "france","spain","italy","sweden","denmark","norway","finland","poland",
    "australia","new zealand","india","canada","mexico","brazil","singapore",
    "japan","israel","portugal","austria","switzerland","belgium","romania",
    "philippines","colombia","argentina","czech","hungary","ukraine","turkey",
    "ontario","alberta","british columbia","quebec","toronto","montreal",
    "calgary","vancouver","sydney","melbourne","london","berlin","amsterdam",
    "paris","madrid","barcelona","munich","dublin","tel aviv","bangalore",
    "bengaluru","mumbai","delhi","manila","bogotá","bogota","mexico city",
]

STATE_ABBR_TO_NAME = {
    "al":"Alabama","ak":"Alaska","az":"Arizona","ar":"Arkansas","ca":"California",
    "co":"Colorado","ct":"Connecticut","de":"Delaware","fl":"Florida","ga":"Georgia",
    "hi":"Hawaii","id":"Idaho","il":"Illinois","in":"Indiana","ia":"Iowa",
    "ks":"Kansas","ky":"Kentucky","la":"Louisiana","me":"Maine","md":"Maryland",
    "ma":"Massachusetts","mi":"Michigan","mn":"Minnesota","ms":"Mississippi",
    "mo":"Missouri","mt":"Montana","ne":"Nebraska","nv":"Nevada","nh":"New Hampshire",
    "nj":"New Jersey","nm":"New Mexico","ny":"New York","nc":"North Carolina",
    "nd":"North Dakota","oh":"Ohio","ok":"Oklahoma","or":"Oregon","pa":"Pennsylvania",
    "ri":"Rhode Island","sc":"South Carolina","sd":"South Dakota","tn":"Tennessee",
    "tx":"Texas","ut":"Utah","vt":"Vermont","va":"Virginia","wa":"Washington",
    "wv":"West Virginia","wi":"Wisconsin","wy":"Wyoming","dc":"Washington DC",
}

STATE_NAME_CANONICAL = {v.lower(): v for v in STATE_ABBR_TO_NAME.values()}
STATE_NAME_CANONICAL["district of columbia"] = "Washington DC"
STATE_NAME_CANONICAL["washington d.c."] = "Washington DC"
STATE_NAME_CANONICAL["washington dc"] = "Washington DC"

def extract_us_states(location_str):
    """Parse a semicolon-separated location string. Returns (is_us, sorted list of state names).
    is_us=True if any part is US-based. Remote with no country is treated as US."""
    parts = [p.strip() for p in location_str.split(";")]
    states = set()
    has_us = False

    for part in parts:
        pl = part.lower()

        # Skip clearly foreign parts
        if any(f in pl for f in FOREIGN_SIGNALS):
            continue

        # Explicit US remote
        if "remote" in pl and ("usa" in pl or "us" in pl or "united states" in pl):
            has_us = True
            states.add("Remote (US)")
            continue

        # Generic remote with no country → assume US
        if re.match(r"^remote\s*$", pl):
            has_us = True
            states.add("Remote (US)")
            continue

        # Check for state names / abbreviations
        found_state = False
        # Full state names first (longest match wins)
        for name, canonical in STATE_NAME_CANONICAL.items():
            if name in pl:
                states.add(canonical)
                has_us = True
                found_state = True

        # Abbreviations: look for ", XX" or standalone "XX" patterns
        if not found_state:
            for abbr, canonical in STATE_ABBR_TO_NAME.items():
                if re.search(r'\b' + abbr + r'\b', pl):
                    states.add(canonical)
                    has_us = True

    return has_us, sorted(states)

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

LEVER_COMPANIES = {
    "Palantir": "palantir",
    "Sophos": "sophos",
    "UltraViolet Cyber": "uvcyber",
    "BlackCloak": "BlackCloak",
}

ASHBY_COMPANIES = {
    "Illumio": "illumio",
    "Snyk": "snyk",
    "1Password": "1password",
    "Drata": "drata",
    "Vanta": "vanta",
    "Semgrep": "semgrep",
    "Socket Security": "socket",
    "Horizon3.ai": "horizon3ai",
    "Lumos": "lumos",
    "WorkOS": "workos",
    "Moxfive": "moxfive",
}

SR_COMPANIES = {
    "Sophos (SR)": "Sophos",
    "Trellix": "Trellix",
    "Fortinet": "Fortinet",
    "Check Point": "CheckPointSoftware",
    "Forcepoint": "Forcepoint",
    "Barracuda Networks": "BarracudaNetworks",
    "Imperva": "Imperva",
    "F5": "F5Networks",
    "CyberArk": "CyberArk",
    "Varonis": "Varonis",
    "Securonix": "Securonix",
}

def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def fetch(token):
    try:
        return _get(f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true")
    except Exception as e:
        print(f"  ! {token}: {e}")
        return None

def fetch_lever(slug):
    try:
        return _get(f"https://api.lever.co/v0/postings/{slug}?mode=json")
    except Exception as e:
        print(f"  ! lever/{slug}: {e}")
        return None

def fetch_ashby(slug):
    try:
        data = _get(f"https://api.ashbyhq.com/posting-api/job-board/{slug}")
        return data.get("jobPostings", [])
    except Exception as e:
        print(f"  ! ashby/{slug}: {e}")
        return None

def fetch_sr(slug):
    try:
        data = _get(f"https://api.smartrecruiters.com/v1/companies/{slug}/postings?limit=100")
        return data.get("content", [])
    except Exception as e:
        print(f"  ! sr/{slug}: {e}")
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
    return (loc.get("name") if isinstance(loc, dict) else str(loc)) or ""

def add_result(results, name, title, loc_raw, url, updated):
    cat = categorize(title)
    if not cat:
        return False
    is_us, states = extract_us_states(loc_raw)
    if not is_us:
        return False
    results.append({
        "company": name,
        "title": title.strip(),
        "category": cat,
        "entry_level": "Yes" if is_entry(title) else "Maybe",
        "location": loc_raw or "—",
        "states": ", ".join(states) if states else "—",
        "url": url,
        "updated": updated,
    })
    return True

results = []
total_boards = len(COMPANIES) + len(LEVER_COMPANIES) + len(ASHBY_COMPANIES) + len(SR_COMPANIES)
print("Fetching live job boards...\n")

print("[Greenhouse]")
for name, token in COMPANIES.items():
    print(f"  - {name}...", end=" ")
    data = fetch(token)
    count = 0
    if data:
        for j in data.get("jobs", []):
            loc = clean_loc(j)
            raw_ts = (j.get("updated_at", "") or "")
            updated = raw_ts[:16].replace("T", " ") if raw_ts else ""
            if add_result(results, name, j.get("title", ""), loc, j.get("absolute_url", ""), updated):
                count += 1
    print(f"{count} matched")

print("\n[Lever]")
for name, slug in LEVER_COMPANIES.items():
    print(f"  - {name}...", end=" ")
    jobs = fetch_lever(slug) or []
    count = 0
    for j in jobs:
        loc = j.get("categories", {}).get("location", "") or ""
        ts = j.get("createdAt", 0)
        updated = datetime.datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M") if ts else ""
        if add_result(results, name, j.get("text", ""), loc, j.get("hostedUrl", ""), updated):
            count += 1
    print(f"{count} matched")

print("\n[Ashby]")
for name, slug in ASHBY_COMPANIES.items():
    print(f"  - {name}...", end=" ")
    jobs = fetch_ashby(slug) or []
    count = 0
    for j in jobs:
        loc = j.get("location", "") or ""
        updated = (j.get("publishedDate", "") or "")[:16].replace("T", " ")
        if add_result(results, name, j.get("title", ""), loc, j.get("jobUrl", ""), updated):
            count += 1
    print(f"{count} matched")

print("\n[SmartRecruiters]")
for name, slug in SR_COMPANIES.items():
    print(f"  - {name}...", end=" ")
    jobs = fetch_sr(slug) or []
    count = 0
    for j in jobs:
        loc_obj = j.get("location", {}) or {}
        parts = [loc_obj.get("city", ""), loc_obj.get("region", ""), loc_obj.get("country", "")]
        loc = ", ".join(p for p in parts if p)
        updated = (j.get("releasedDate", "") or "")[:16].replace("T", " ")
        url = f"https://careers.smartrecruiters.com/{slug}/{j.get('id', '')}"
        if add_result(results, name, j.get("name", ""), loc, url, updated):
            count += 1
    print(f"{count} matched")

# Sort: cyber first, then entry-level first, then company, then state
results.sort(key=lambda r: (r["category"] != "Cybersecurity",
                            r["entry_level"] != "Yes",
                            r["company"],
                            r["states"]))

print(f"\nTOTAL matched roles: {len(results)}")
cyber = sum(1 for r in results if r['category']=='Cybersecurity')
it = sum(1 for r in results if r['category']=='IT / On-Ramp')
print(f"  Cybersecurity: {cyber}   IT/On-Ramp: {it}")

# ---------- CSV ----------
with open(os.path.join(OUT_DIR, "cyber_jobs.csv"),"w",newline="",encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["company","title","category","entry_level","states","location","updated","url"])
    w.writeheader()
    for r in results: w.writerow(r)

# ---------- Markdown ----------
with open(os.path.join(OUT_DIR, "cyber_jobs.md"),"w",encoding="utf-8") as f:
    f.write(f"# Cybersecurity & IT Job Tracker\n\n")
    f.write(f"_Last updated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} ET — {len(results)} roles from {total_boards} company boards_\n\n")
    f.write("| Company | Role | Category | Entry? | States | Location | Posted | Apply |\n")
    f.write("|---|---|---|---|---|---|---|---|\n")
    for r in results:
        f.write(f"| {r['company']} | {r['title']} | {r['category']} | {r['entry_level']} | {r['states']} | {r['location']} | {r['updated'] or '—'} | [Apply]({r['url']}) |\n")

# ---------- HTML ----------
rows_html = ""
all_states = sorted({s for r in results for s in r["states"].split(", ") if s != "—"})
for r in results:
    badge = "#2E75B6" if r["category"]=="Cybersecurity" else "#70AD47"
    entry_badge = "#1F7A1F" if r["entry_level"]=="Yes" else "#B8860B"
    rows_html += f"""<tr data-cat="{r['category']}" data-entry="{r['entry_level']}" data-states="{html.escape(r['states'])}">
      <td><b>{html.escape(r['company'])}</b></td>
      <td>{html.escape(r['title'])}</td>
      <td><span style="background:{badge};color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;">{r['category']}</span></td>
      <td><span style="color:{entry_badge};font-weight:600;">{r['entry_level']}</span></td>
      <td>{html.escape(r['states'])}</td>
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
<div class="sub">Auto-generated {datetime.date.today()} · {len(results)} roles from {total_boards} live company boards · {cyber} cyber / {it} IT</div>
<div class="controls">
  <button onclick="applyFilters('all',null)">All</button>
  <button onclick="applyFilters('Cybersecurity',null)">Cybersecurity</button>
  <button onclick="applyFilters('IT / On-Ramp',null)">IT / On-Ramp</button>
  <button class="alt" onclick="entryOnly()">Entry-Level Only</button>
  <button class="alt" onclick="reset()">Reset</button>
  <select id="stateFilter" onchange="applyFilters(null,this.value)" style="margin-left:8px;padding:7px 10px;border-radius:6px;border:1px solid #ccc;font-size:14px;">
    <option value="">— Filter by State —</option>
    {''.join(f'<option value="{s}">{s}</option>' for s in all_states)}
  </select>
</div>
<table id="t">
<thead><tr><th>Company</th><th>Role</th><th>Category</th><th>Entry?</th><th>States</th><th>Location</th><th>Updated</th><th>Link</th></tr></thead>
<tbody>{rows_html}</tbody></table>
<script>
var activeCat='all', activeState='';
function applyFilters(cat,state){{
  if(cat!==null) activeCat=cat;
  if(state!==null) activeState=state;
  document.querySelectorAll('#t tbody tr').forEach(r=>{{
    var catOk = activeCat==='all'||r.dataset.cat===activeCat;
    var stateOk = !activeState||r.dataset.states.includes(activeState);
    r.style.display = (catOk&&stateOk)?'':'none';
  }});
}}
function entryOnly(){{
  document.querySelectorAll('#t tbody tr').forEach(r=>{{
    var stateOk = !activeState||r.dataset.states.includes(activeState);
    r.style.display=(r.dataset.entry==='Yes'&&stateOk)?'':'none';
  }});
}}
function reset(){{
  activeCat='all'; activeState='';
  document.getElementById('stateFilter').value='';
  document.querySelectorAll('#t tbody tr').forEach(r=>r.style.display='');
}}
</script>
</body></html>"""
with open(os.path.join(OUT_DIR, "cyber_jobs.html"),"w",encoding="utf-8") as f:
    f.write(html_doc)

print("\nGenerated: cyber_jobs.html, cyber_jobs.csv, cyber_jobs.md")
