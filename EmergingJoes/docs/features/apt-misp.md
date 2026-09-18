# APT groups & MISP export

Page: `/apt`.

## Behavior

1. APT mentions are consolidated from article summaries using MITRE-oriented registry helpers (`apt_registry.py`, `mitre_data.py`).  
2. Analyst can extract IOCs from an article (`ioc_extractor.py`) and export to MISP (`misp_client.py`, `apt_ioc_processor.py`).  
3. Export attempts are stored in `apt_ioc_exports` (`status`, event id/uuid, galaxy tag, errors).  

## Configuration

Settings → MISP:

- Instance URL  
- API key  
- Optional live/enable toggles depending on deployment  

Connectivity check: `GET /api/misp/status`.

## Notes for agents

- PyMISP API names differ across versions; this codebase uses compatible helpers such as instance version and galaxy cluster search (avoid obsolete `get_version` / `galaxy_clusters` if they fail).  
- IOC extraction can false-positive on times, `.dll` fragments, etc. — tighten filters when improving quality.  
- Names reserved for documentation (RFC 2606/6761: `example.com/net/org`, `.test`, `.invalid`, `.localhost`, and any subdomain of them) are rejected as domains *and* as the domain part of an email address. Articles use them in example commands — a MikroTik RouterOS write-up produced `router.example.net` as its only "indicator" — and exporting them publishes indicators that can never match real activity.  
- Local Docker MISP under `misp/misp-docker` is optional and large; prefer documenting remote MISP.live or an existing instance for most installs.  
