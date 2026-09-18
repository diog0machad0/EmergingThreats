# Install notes — JOES Threat Intelligence

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Python 3.10+** | 3.11/3.12 recommended |
| **pip / venv** | Standard library `venv` is enough |
| **LLM API key** | OpenAI **or** Anthropic **or** OpenRouter (Settings / `.env`) |
| **OpenAI key (optional)** | Still needed for **embeddings** / intelligence search if you use those features and provider is not OpenAI |
| **System libs for Scriba** | WeasyPrint needs Pango/Cairo (see below) — only required for PDF advisories |
| **Docker (optional)** | Only if you run local MISP via `misp/` |

Optional:

- Malpedia API key — research feed ingestion  
- SMTP credentials — email digests / alerts  
- MISP URL + API key — APT IOC export  

## Repository layout

```
emergingJoes/
├── EmergingJoes/          # Main Flask application
├── scriba/              # Advisory PDF builder
├── misp/                # Optional MISP setup scripts
├── INSTALL.md
├── AGENT_HANDOFF.md
└── README.md
```

## 0. Single-command launch (recommended)

`start.py` at the repo root is the one entry point. From a bare clone it creates
both virtualenvs (EmergingJoes + Scriba), installs their requirements, seeds
`.env` and `data/config.json` from the checked-in examples, then starts the app.
It needs only the standard library, so it runs before anything is installed.

```bash
python start.py             # provision if needed, then serve
./start.sh                  # macOS / Linux wrapper
start.bat                   # Windows wrapper
```

| Flag | Effect |
|------|--------|
| `--setup-only` | provision and exit without serving |
| `--reinstall` | reinstall dependencies even if they look current |
| `--host` / `--port` | override bind address and port |
| `--skip-scriba` | skip the PDF renderer venv (advisory PDFs will not work) |

Repeat runs are cheap: each venv keeps a stamp of its `requirements.txt`, so pip
is skipped when nothing changed.

The address comes from `HOST`/`PORT` in `EmergingJoes/.env`, falling back to
`127.0.0.1` on a free port. Add an LLM key in **Settings** before summarizing.

The manual steps below remain valid if you prefer to drive each piece yourself.

## 1. EmergingJoes (main app) — manual setup

```bash
cd EmergingJoes
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env — at least one LLM key + preferred provider

cp data/config.json.example data/config.json   # if config does not exist yet
# Or let first run create config from example

# Recommended local bind for this fork:
export HOST=127.0.0.1
export PORT=5050
python app.py
```

Or use the per-app helper:

```bash
chmod +x run.sh
./run.sh
# Override: HOST=127.0.0.1 PORT=5050 ./run.sh
```

Open: `http://127.0.0.1:5050` (or the port you set).

### Environment variables (EmergingJoes)

See `.env.example`. Important keys:

| Variable | Purpose |
|----------|---------|
| `HOST` / `PORT` / `DATA_DIR` | Bind address & SQLite/config directory |
| `LLM_PROVIDER` | `openai` \| `anthropic` \| `openrouter` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | OpenAI chat (+ embeddings) |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | Anthropic chat |
| `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` | OpenRouter (OpenAI-compatible) |
| `MALPEDIA_API_KEY` | Optional research ingestion |
| SMTP_* / `NOTIFICATION_EMAIL` | Optional email |

Runtime settings are also stored in `data/config.json` (UI Settings page). Prefer Settings for day-to-day changes; `.env` seeds local secrets.

> **`.env` overrides Settings.** `config.py` lets `LLM_PROVIDER` and the `*_API_KEY`
> variables override whatever is saved in `config.json`. If a value is set in `.env`,
> changing it in the Settings UI has no effect until you clear it. Leave these blank
> in `.env` if you want to manage the provider from the UI. Likewise, setting
> `NOTIFICATION_EMAIL` auto-enables per-article email.

**Do not commit** `.env`, `data/config.json`, or `data/*.db`.

### Choosing an LLM model

Pin a **concrete** model. Do not use OpenRouter's `openrouter/free` alias: it routes
each call to an arbitrary free model, including reasoning models that emit
chain-of-thought where the summarizer expects strict JSON, which causes parse
failures and retries.

**OpenRouter free tier is capped at 50 requests/day per account.** The pipeline
spends roughly one request per article (plus batched relevance checks and one
enrichment call per customer-matched article), so a single 100+ article refresh
exhausts the daily quota. Once exhausted, every call returns HTTP 429
(`free-models-per-day`). Options:

| Option | Cost | Notes |
|--------|------|-------|
| Add 10 credits to OpenRouter | one-off $10 | Raises the cap to 1000 free-model requests/day; `:free` models still bill $0 per token |
| Paid model (e.g. `gpt-4.1-mini`) | per token | The handoff baseline; most reliable JSON |
| Self-hosted / local OpenAI-compatible endpoint | free | Unlimited, but needs `llm_client.py` to accept a custom base URL |

Verify a model is still listed before pinning it — free model IDs are retired
regularly:

```bash
curl -s https://openrouter.ai/api/v1/models | \
  python -c "import json,sys; print('\n'.join(m['id'] for m in json.load(sys.stdin)['data'] if m['pricing']['prompt']=='0'))"
```

### Docker (EmergingJoes only)

```bash
cd EmergingJoes
cp .env.example .env
docker compose up
```

Default compose port is typically `5000` unless overridden.

## 2. Scriba (advisory PDFs)

Required for **Create advisory** (vulnerability + threat intelligence).

### OS packages (WeasyPrint)

**macOS (Homebrew):**

```bash
brew install pango cairo gdk-pixbuf libffi
```

**Debian/Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
  libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info
```

### Python env

```bash
cd scriba
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

EmergingJoes’s `advisory_generator.py` prefers `scriba/.venv/bin/python` when present; otherwise it uses the EmergingJoes interpreter (WeasyPrint must be importable there too).

Template used by the LLM: `scriba/reports/sample_advisory.md`  
Generated markdown: `scriba/reports/`  
Generated PDFs: `scriba/output/`

## 3. MISP (optional)

Local MISP is **not** required to run EmergingJoes. For APT export:

1. Point Settings → MISP at a reachable instance (e.g. MISP.live or self-hosted).  
2. Or follow `misp/README.md` / `misp/setup.sh` for Docker (large download).  

API helpers live in `EmergingJoes/misp_client.py`.

## 4. First-run checklist

1. Start EmergingJoes; open Settings; set LLM provider + key; **Test** key.  
2. Confirm Customers exist (defaults may seed on `init_db`).  
3. Trigger **Refresh** (1 day) from the header; approve cost gate when prompted.  
4. Open **Emerging Threats** → Threat Intelligence / Vulnerabilities queues.  
5. (Optional) Create an advisory; confirm PDF download + Advisories tab.  
6. (Optional) Mark items **Triaged**; confirm they leave the default queue.  

### Clear / reset database

```bash
curl -s -X POST http://127.0.0.1:5050/api/clear-db \
  -H 'Content-Type: application/json' -d '{}'
```

Or Settings UI “Clear database”. Preserves sources & customers; wipes articles/analyses/advisories.

## 5. Requirements files

| File | Contents |
|------|----------|
| `EmergingJoes/requirements.txt` | Flask, feedparser, trafilatura, openai, anthropic, apscheduler, numpy, pymisp, … |
| `scriba/requirements.txt` | jinja2, markdown-it-py, weasyprint, … |

Pin loosely with `>=` for flexibility; for production GitHub deploys, freeze with `pip freeze > requirements.lock.txt` after a successful install.

## 6. Common ports & run commands

```bash
# Typical JOES Threat Intelligence local session
python start.py

# Or drive the app directly
cd EmergingJoes && source venv/bin/activate
HOST=127.0.0.1 PORT=5050 python app.py
```

Pipeline:

```bash
curl -X POST http://127.0.0.1:5050/api/refresh -H 'Content-Type: application/json' -d '{"days":1}'
# When stage=confirm:
curl -X POST http://127.0.0.1:5050/api/cost/approve
curl http://127.0.0.1:5050/api/refresh-status
curl http://127.0.0.1:5050/api/stats
```

## 7. GitHub push hygiene

Include:

- Source, templates, static assets, docs, `requirements.txt`, `.env.example`, `data/config.json.example`  
- `scriba/src`, templates, styles, assets, `sample_advisory.md`  

Exclude:

- `venv/`, `.venv/`, `__pycache__/`  
- `.env`, `data/config.json`, `data/*.db*`  
- `scriba/output/*.pdf`, bulk generated reports (keep sample)  
- `misp/misp-docker/` (huge; document as optional clone)  
- Demo videos / large binaries unless needed  

Root `.gitignore` and `EmergingJoes/.gitignore` should already cover secrets and DBs.
