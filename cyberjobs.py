"""
CyberJobs Aggregator — pulls live entry-level cybersecurity & IT roles
from public Greenhouse job-board APIs, filters/categorizes them, and
outputs HTML, CSV, and Markdown. Demo build.
"""
import json, csv, urllib.request, datetime, html, re, os, urllib.parse

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
            "associate", "early career", "university", "apprentice",
            "level 1", "tier 1", "trainee"]
SENIOR_BLOCK = ["senior", "staff", "principal", "lead", "manager", "director",
                "head of", "vp ", "vice president", "chief ", "ciso", "cto", "ceo",
                "ii", "iii", "iv", " 2", " 3", "sr.", "architect", "consultant"]

# Phrases in job descriptions that signal entry-level / new-grad roles
ENTRY_DESC_KW = [
    "0-2 years", "0 to 2 years", "0 - 2 years",
    "0-1 years", "0 to 1 year", "1-2 years", "1 to 2 years",
    "0+ years", "1+ year", "up to 2 years",
    "no experience required", "no prior experience",
    "new grad", "new graduate", "recent grad", "recent graduate",
    "fresh graduate", "college graduate", "university graduate",
    "entry level", "entry-level",
    "early career", "early-career",
    "bachelor", "bs/ba", "b.s.", "b.a.",
    "0 years of experience", "less than 1 year",
]

def strip_html(raw):
    """Unescape HTML entities and strip tags, return lowercase plain text."""
    unescaped = html.unescape(raw or "")
    plain = re.sub(r'<[^>]+>', ' ', unescaped)
    return re.sub(r'\s+', ' ', plain).strip().lower()

def is_entry_from_desc(desc_plain):
    """Return True if description contains new-grad / entry-level signals."""
    return any(k in desc_plain for k in ENTRY_DESC_KW)

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

def add_result(results, name, title, loc_raw, url, updated, desc_raw=""):
    cat = categorize(title)
    if not cat:
        return False
    is_us, states = extract_us_states(loc_raw)
    if not is_us:
        return False
    desc_plain = strip_html(desc_raw)
    has_senior = any(k in title.lower() for k in SENIOR_BLOCK)
    entry_title = is_entry(title)
    entry_desc = not has_senior and is_entry_from_desc(desc_plain)
    if entry_title:
        entry_label = "Yes"
    elif entry_desc:
        entry_label = "Yes (desc)"
    else:
        entry_label = "Maybe"
    results.append({
        "company": name,
        "title": title.strip(),
        "category": cat,
        "entry_level": entry_label,
        "location": loc_raw or "—",
        "states": ", ".join(states) if states else "—",
        "url": url,
        "updated": updated,
        "is_new": url not in seen_urls,
    })
    return True

# Load previously seen job URLs
SEEN_PATH = os.path.join(OUT_DIR, "seen_jobs.json")
try:
    with open(SEEN_PATH, "r", encoding="utf-8") as f:
        seen_urls = set(json.load(f))
except (FileNotFoundError, json.JSONDecodeError):
    seen_urls = set()

results = []
total_boards = len(COMPANIES) + len(LEVER_COMPANIES) + len(ASHBY_COMPANIES) + len(SR_COMPANIES) + 1  # +1 Remote OK
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
            desc = j.get("content", "") or ""
            if add_result(results, name, j.get("title", ""), loc, j.get("absolute_url", ""), updated, desc):
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
        desc = j.get("descriptionPlain", "") or j.get("description", "") or ""
        if add_result(results, name, j.get("text", ""), loc, j.get("hostedUrl", ""), updated, desc):
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
        desc = j.get("descriptionPlain", "") or j.get("description", "") or ""
        if add_result(results, name, j.get("title", ""), loc, j.get("jobUrl", ""), updated, desc):
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

print("\n[Remote OK]")
try:
    req = urllib.request.Request(
        "https://remoteok.com/api?tag=security",
        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        rok_jobs = [j for j in json.loads(r.read().decode()) if isinstance(j, dict) and j.get("position")]
    count = 0
    for j in rok_jobs:
        loc = j.get("location", "") or "Remote (US)"
        ts = j.get("epoch", 0)
        updated = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""
        desc = strip_html(j.get("description", "") or "")
        company = j.get("company", "Unknown")
        if add_result(results, company, j.get("position", ""), loc, j.get("url", ""), updated, desc):
            count += 1
    print(f"  Remote OK... {count} matched")
except Exception as e:
    print(f"  Remote OK... failed ({e})")

USAJOBS_KEY = os.environ.get("USAJOBS_KEY", "")
if USAJOBS_KEY:
    print("\n[USAJobs]")
    params = urllib.parse.urlencode({
        "Keyword": "cybersecurity information security IT support help desk",
        "ResultsPerPage": 500,
        "JobCategoryCode": "2210;0080",  # IT Management + Security Administration
    })
    req = urllib.request.Request(
        f"https://data.usajobs.gov/api/search?{params}",
        headers={"User-Agent": USAJOBS_KEY, "Host": "data.usajobs.gov", "Authorization-Key": USAJOBS_KEY}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            usa_data = json.loads(r.read().decode())
        count = 0
        for item in usa_data["SearchResult"]["SearchResultItems"]:
            j = item["MatchedObjectDescriptor"]
            title = j.get("PositionTitle", "")
            loc = j.get("PositionLocationDisplay", "")
            url = j.get("PositionURI", "")
            updated = (j.get("PublicationStartDate", "") or "")[:16].replace("T", " ")
            org = j.get("OrganizationName", "")
            desc = j.get("UserArea", {}).get("Details", {}).get("JobSummary", "") or ""
            low_grade = j.get("UserArea", {}).get("Details", {}).get("LowGrade", "")
            # Treat GS-5 through GS-9 as entry-level signal in description
            if low_grade and int(low_grade) <= 9:
                desc = desc + " entry level 0-2 years recent graduate"
            if add_result(results, f"USAJobs – {org}", title, loc, url, updated, desc):
                count += 1
        print(f"  USAJobs... {count} matched")
    except Exception as e:
        print(f"  USAJobs... failed ({e})")
else:
    print("\n[USAJobs] skipped — set USAJOBS_KEY env var to enable")

# Save seen URLs for next run
with open(SEEN_PATH, "w", encoding="utf-8") as f:
    json.dump(list({r["url"] for r in results}), f)

new_count = sum(1 for r in results if r["is_new"])

# Sort: new first, then cyber first, entry "Yes" before "Yes (desc)" before "Maybe", then company
ENTRY_ORDER = {"Yes": 0, "Yes (desc)": 1, "Maybe": 2}
results.sort(key=lambda r: (not r["is_new"],
                            r["category"] != "Cybersecurity",
                            ENTRY_ORDER.get(r["entry_level"], 2),
                            r["company"],
                            r["states"]))

print(f"\nTOTAL matched roles: {len(results)}  ({new_count} new since last run)")
cyber = sum(1 for r in results if r['category']=='Cybersecurity')
it = sum(1 for r in results if r['category']=='IT / On-Ramp')
print(f"  Cybersecurity: {cyber}   IT/On-Ramp: {it}")

# ---------- CSV ----------
with open(os.path.join(OUT_DIR, "cyber_jobs.csv"),"w",newline="",encoding="utf-8") as f:
    fields = ["company","title","category","entry_level","states","location","updated","url","is_new"]
    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in results: w.writerow(r)

# ---------- Markdown ----------
with open(os.path.join(OUT_DIR, "cyber_jobs.md"),"w",encoding="utf-8") as f:
    f.write(f"# Cybersecurity & IT Job Tracker\n\n")
    f.write(f"_Last updated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} ET — {len(results)} roles from {total_boards} company boards · {new_count} new since last run_\n\n")
    f.write("| Company | Role | Category | Entry? | States | Location | Posted | Apply |\n")
    f.write("|---|---|---|---|---|---|---|---|\n")
    for r in results:
        new_tag = " 🆕" if r["is_new"] else ""
        f.write(f"| {r['company']} | {r['title']}{new_tag} | {r['category']} | {r['entry_level']} | {r['states']} | {r['location']} | {r['updated'] or '—'} | [Apply]({r['url']}) |\n")

# ---------- HTML ----------
rows_html = ""
all_states = sorted({s for r in results for s in r["states"].split(", ") if s != "—"})
for r in results:
    badge = "#2E75B6" if r["category"]=="Cybersecurity" else "#70AD47"
    entry_badge = "#1F7A1F" if r["entry_level"]=="Yes" else ("#2E8B57" if r["entry_level"]=="Yes (desc)" else "#B8860B")
    new_badge = '<span style="background:#e63946;color:#fff;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:700;margin-left:5px;">NEW</span>' if r["is_new"] else ""
    rows_html += f"""<tr data-cat="{r['category']}" data-entry="{r['entry_level']}" data-states="{html.escape(r['states'])}" data-new="{str(r['is_new']).lower()}">
      <td><b>{html.escape(r['company'])}</b></td>
      <td>{html.escape(r['title'])}{new_badge}</td>
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
<div class="sub">Last updated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} ET · {len(results)} roles from {total_boards} live company boards · {cyber} cyber / {it} IT · <b style="color:#e63946">{new_count} new</b></div>
<div class="controls">
  <button onclick="applyFilters('all',null)">All</button>
  <button onclick="applyFilters('Cybersecurity',null)">Cybersecurity</button>
  <button onclick="applyFilters('IT / On-Ramp',null)">IT / On-Ramp</button>
  <button class="alt" onclick="entryOnly()">Entry-Level Only</button>
  <button class="alt" onclick="newOnly()" style="background:#e63946;">New Only</button>
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
    var isEntry = r.dataset.entry==='Yes'||r.dataset.entry==='Yes (desc)';
    r.style.display=(isEntry&&stateOk)?'':'none';
  }});
}}
function newOnly(){{
  document.querySelectorAll('#t tbody tr').forEach(r=>{{
    r.style.display=(r.dataset.new==='true')?'':'none';
  }});
}}
function reset(){{
  activeCat='all'; activeState='';
  document.getElementById('stateFilter').value='';
  document.querySelectorAll('#t tbody tr').forEach(r=>r.style.display='');
}}
</script>
</body></html>"""
with open(os.path.join(OUT_DIR, "index.html"),"w",encoding="utf-8") as f:
    f.write(html_doc)

print("\nGenerated: index.html, cyber_jobs.csv, cyber_jobs.md")
