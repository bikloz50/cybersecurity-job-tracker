# CyberJobs Aggregator

A self-updating job aggregator for **entry-level cybersecurity and IT roles**,
inspired by the Simplify / New-Grad-Positions GitHub repos — but focused on
cyber + IT on-ramp roles instead of SWE.

It pulls live postings from public company job boards (Greenhouse API),
filters and categorizes them, flags likely entry-level roles, and outputs
a browsable HTML page, a CSV, and a Markdown table.

## What it does
- Fetches roles from configured company boards (no API key needed)
- Keeps only **Cybersecurity** or **IT / On-Ramp** roles
- Flags entry-level (Yes/Maybe) by detecting junior signals & filtering seniors
- Outputs: `cyber_jobs.html` (filterable), `cyber_jobs.csv`, `cyber_jobs.md`

## Setup (one time)
1. Install Python 3 (python.org) if you don't have it.
2. No external libraries needed — it uses only the Python standard library.

## Run it
```bash
python cyberjobs.py
```
Then open `cyber_jobs.html` in your browser. Use the buttons to filter by
category or show entry-level only.

## Add more companies
Edit the `COMPANIES` dict at the top. The value is the company's Greenhouse
"board token" — find it in their careers URL:
`boards.greenhouse.io/{token}`. Many security-heavy employers use Greenhouse.
Other boards (Lever, Ashby, Workday) use different APIs and would need their
own fetch function — a good "v2" upgrade.

## Tune the filters
- `CYBER_KW` / `IT_KW` — keywords that decide the category
- `ENTRY_KW` — signals a role is junior
- `SENIOR_BLOCK` — signals to exclude from "entry-level"
Adjust these to widen or narrow what shows up.

## Make it auto-update (advanced / portfolio upgrade)
Push this to your own GitHub repo and add a GitHub Actions workflow on a
schedule (cron) that runs `cyberjobs.py` and commits the refreshed outputs.
That replicates how the big Simplify-style repos stay current — and it's a
great thing to show employers.

## Resume / portfolio note
This project demonstrates: API consumption, data parsing/filtering,
text classification heuristics, and multi-format reporting (HTML/CSV/MD).
Good talking points for an entry-level security or IT interview.
