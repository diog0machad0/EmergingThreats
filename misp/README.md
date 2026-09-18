# MISP for JOES Threat Intelligence

Threat intelligence platform integration for APT IOC export.

## Quick start

```bash
cd misp
chmod +x setup.sh
./setup.sh
```

First boot can take **5–15 minutes**. MISP will be available at:

- **URL:** https://127.0.0.1:8443
- **Login:** admin@emerging-joes.local / `Admin1234!`

The setup script writes the generated API key into `EmergingJoes/data/config.json` (or set it manually under **Settings → MISP**).

## How IOC export works

When an article is summarized with a known APT tag **and** contains IOCs:

1. IOCs are extracted (regex + LLM enrichment)
2. A MISP event is created with attributes (IP, domain, hash, URL, etc.)
3. The event is tagged with the **Threat Actor galaxy** cluster (e.g. `misp-galaxy:threat-actor="APT29"`)
4. Article URL, campaign name, and context are stored in attribute comments

View exports on the **APT** page in JOES Threat Intelligence.

## Manual commands

```bash
cd misp/misp-docker
docker compose ps
docker compose logs -f misp-core
docker compose down
```

## Configuration keys (`EmergingJoes/data/config.json`)

| Key | Description |
|-----|-------------|
| `misp_enabled` | Enable/disable export |
| `misp_url` | MISP base URL |
| `misp_api_key` | Admin auth key |
| `misp_verify_ssl` | Set `false` for self-signed local cert |
