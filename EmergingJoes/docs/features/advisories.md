# Advisories

Advisories are **tracked in SQLite** and **authored as Scriba Markdown/PDF**.

## Design intent

The database records that an advisory **was made** for a given CVE and/or source article (plus metadata and PDF filename). It does **not** store the full advisory body. Content lives under the sibling `scriba/` project.

## Table: `advisories`

Key fields: `kind`, `article_id`, `cve_id`, `technology`, `title`, `stem` (UNIQUE), `pdf_filename`, `markdown_path`, `pdf_path`, `customer_id`, `customer_name`, `created_date`.

| kind | Source |
|------|--------|
| `vulnerability` | CVE + tech from Vulnerabilities tab |
| `threat_intelligence` | Customer-matched TI article |
| `general` | Imported / backfilled Scriba outputs |

## Generation flow

1. Analyst opens match → **Create advisory**  
2. `advisory_generator.py` calls LLM with `scriba/reports/sample_advisory.md` as template  
3. Writes markdown to `scriba/reports/<stem>.md`  
4. Runs Scriba build → `scriba/output/<stem>.pdf`  
5. `save_advisory(...)` upserts DB row by `stem`  

PDF download: `GET /api/advisories/pdf/<filename>`.

## UI

Emerging Threats → **Advisories**:

- All advisories  
- Vulnerability advisories  

TI advisories appear under **All**. Cards show kind badge, CVE (if any), customer, download link.

## Backfill

`backfill_advisories_from_scriba()` scans existing PDFs in `scriba/output/` and inserts missing DB rows (used on startup / ops recovery).
