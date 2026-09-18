# Agent handoff — JOES Threat Intelligence

Use this document to onboard a new engineer or coding agent. For install steps see [INSTALL.md](INSTALL.md). For product overview see [README.md](README.md).

---

## Starter prompt (copy-paste to the next agent)

```text
You are continuing work on JOES Threat Intelligence, the Security Joes operational
CTI platform (app code in EmergingJoes/). Read these files first, in order:

1. README.md
2. INSTALL.md
3. AGENT_HANDOFF.md  (this file)
4. EmergingJoes/docs/architecture.md
5. EmergingJoes/docs/features/emerging-threats-ops.md
6. EmergingJoes/docs/features/advisories.md
7. EmergingJoes/docs/features/apt-misp.md

Project goals: operational CTI for analysts — feed ingestion + LLM summarization, then
customer-mapped Threat Intelligence and Vulnerability queues with triage, Scriba PDF
advisories tracked in SQLite (linkage only, not full advisory body in DB), and APT IOC
export to MISP.

Key code:
- EmergingJoes/app.py — Flask routes
- EmergingJoes/database.py — SQLite schema + queries (incl. triage_status)
- EmergingJoes/scheduler.py — fetch → scrape → cost gate → summarize → embed
- EmergingJoes/emerging_threats.py / vulnerability_threats.py — customer matching
- EmergingJoes/advisory_generator.py — LLM markdown + Scriba PDF
- EmergingJoes/llm_client.py — openai | anthropic | openrouter
- scriba/ — PDF build (sample: scriba/reports/sample_advisory.md)
- UI: EmergingJoes/templates/emerging_threats.html, apt.html, customers.html, settings.html

Conventions:
- Prefer HOST=127.0.0.1 PORT=5050 for local runs
- Advisories DB rows track that an advisory was made for a CVE/article (stem, pdf path, kind)
- Triage hides items from default queue (pending) but does not delete analyses
- Re-analysis must NOT reset triage_status
- Do not commit .env, data/config.json, or SQLite DB files
- Do not put full advisory markdown/PDF bytes into SQLite

Before coding: skim git status / recent modules above. Confirm the app starts and
/api/stats returns has_api_key. Ask the user what the next feature priority is if unclear.

Known recent verification (clean DB, 1-day refresh): 36 articles summarized, TI queue
populated, vuln match + advisory PDF + triage OK. MISP optional.
```

---

## Architecture snapshot

```
Feeds / Malpedia
    → scrape
    → LLM summarize (+ customer TI match hook)
    → embed
         ↓
SQLite: articles, summaries, emerging_threat_analyses, vulnerability_analyses,
        customers, advisories, apt_ioc_exports, …
         ↓
UI queues: Emerging Threats (TI | Vulnerabilities | Advisories)
         ↓
Optional: Scriba PDF · MISP event export
```

### Important modules

| Module | Responsibility |
|--------|----------------|
| `app.py` | Pages + REST API |
| `scheduler.py` | Pipeline lock, cost confirm, abort |
| `database.py` | Schema, migrations (`ALTER` for new columns), CRUD |
| `llm_client.py` | Provider routing + token accounting hooks |
| `emerging_threats.py` | Deterministic footprint match + LLM enrichment |
| `vulnerability_threats.py` | CVE + tech-stack hits |
| `advisory_generator.py` | CVE & TI advisory generation |
| `misp_client.py` / `apt_*` | APT consolidation + MISP |
| `ioc_extractor.py` | IOC parsing (watch false positives) |

### Emerging Threats UX

- Tab **Threat Intelligence** (was “Customer based”): customer-matched articles  
- Tab **Vulnerabilities**: CVE + customer tech  
- Tab **Advisories**: All | Vulnerability-specific  
- Default list filter: `triage_status=pending`  
- **Mark as Triaged** → leaves queue; **Restore to queue** from Triaged filter  
- **Open & create advisory** on TI and Vuln cards  

### Advisories semantics

- DB knows an advisory **was made** for `cve_id` and/or `article_id`  
- Kinds: `vulnerability`, `threat_intelligence`, `general`  
- Full content lives in `scriba/reports/*.md` + `scriba/output/*.pdf`  
- Serve PDF via `/api/advisories/pdf/<filename>`  

---

## API map (operational)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/emerging-threats?triage_status=pending\|triaged\|all` | TI queue |
| GET | `/api/emerging-threats/<id>` | Detail |
| POST | `/api/emerging-threats/advisory` | TI advisory (no CVE required) |
| POST | `/api/emerging-threats/<id>/triage` | `{ "triage_status": "triaged"\|"pending" }` |
| POST | `/api/emerging-threats/analyze-missing` | Backfill TI analysis |
| GET | `/api/vulnerabilities?triage_status=…` | Vuln queue |
| POST | `/api/vulnerabilities/advisory` | Needs `article_id`, `cve_id`, `matched_tech` |
| POST | `/api/vulnerabilities/<id>/triage` | Same as TI |
| GET | `/api/advisories?kind=all\|vulnerability\|threat_intelligence` | List |
| POST | `/api/refresh` | `{ "days": 1 }` |
| POST | `/api/cost/approve` | After stage `confirm` |
| POST | `/api/clear-db` | Full wipe of articles/analyses |
| GET | `/api/misp/status` | MISP connectivity |
| GET | `/api/apt-groups` | APT list |

---

## Database tables (ops layer)

Added / extended beyond classic EmergingJoes:

- `customers` — footprint fields (JSON affiliates / tech stack)  
- `emerging_threat_analyses` — `hits_json`, **`triage_status`**, `triaged_date`  
- `vulnerability_analyses` — same triage fields  
- `advisories` — stem UNIQUE, kind, article_id, cve_id, pdf_filename, …  
- `apt_ioc_exports` — MISP export status  

Migrations: `init_db()` uses `CREATE TABLE IF NOT EXISTS` + best-effort `ALTER TABLE` for new columns. Indexes that depend on new columns are created **after** alters.

---

## Configuration

- Secrets: `EmergingJoes/.env` (from `.env.example`)  
- App config: `EmergingJoes/data/config.json` (from `config.json.example`)  
- LLM provider in Settings: `openai` | `anthropic` | `openrouter`  
- MISP URL/key in Settings (PyMISP; prefer `misp_instance_version` / galaxy search helpers already patched for newer PyMISP)  

---

## Verified workflows (handoff baseline)

On a cleared DB + 1-day refresh (Sep 2026 test):

1. LLM smoke OK (`gpt-4.1-mini`)  
2. 36 articles fetched/scraped/summarized; scrape_failed=0  
3. TI queue filled (customer matches during summarize)  
4. Vuln analyze produced ≥1 CVE hit; advisory PDF generated (~11s)  
5. Triage removed items from pending queues without deleting rows  

---

## Likely next work (not committed as requirements)

Suggestions only — confirm with product owner:

- TI advisory UX polish / richer kind filters in Advisories tab  
- Stronger CVE validation / NVD enrichment  
- IOC extractor false-positive reduction  
- MISP.live auth / galaxy tagging edge cases  
- Packaging: CI, lockfiles, omit `misp-docker` from default clone  
- Multi-analyst triage ownership / audit trail  

---

## Safety / secrets

- Never commit API keys, MISP keys, or DB dumps with customer data  
- `clear_database()` does not delete `customers` or `sources`  
- Cost gate can auto-approve after 5 minutes if unattended — be careful in prod  

---

## Package contents

If you received `emergingJoes-handoff.zip`, unpack and follow [INSTALL.md](INSTALL.md). The ZIP excludes virtualenvs, `.env`, SQLite DBs, and the bulky `misp-docker` tree.
