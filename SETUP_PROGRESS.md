# EmergingJoes Setup — Progress Log

**Project:** JOES Threat Intelligence (app code in `EmergingJoes/`)  
**Repository:** [diog0machad0/EmergingThreats](https://github.com/diog0machad0/EmergingThreats)  
**Last updated:** 2026-05-15

---

## Stage overview

| Stage | Status | Notes |
|-------|--------|-------|
| 1. Acquire source | **Done** | Cloned into `EmergingJoes/` |
| 2. Local Python environment | **Done** | `venv/` + `pip install -r requirements.txt` |
| 3. Config bootstrap | **Done** | `.env` from `.env.example`; `data/config.json` created on first run |
| 4. Runtime verification | **Done** | App starts; `/` and `/api/stats` return 200 |
| 5. API keys for full pipeline | **Pending (you)** | Summarization, embeddings, RAG need real keys |
| 6. Adaptation for emergingJoes | **Not started** | Next phase after keys + requirements are clear |

---

## What EmergingJoes does

**JOES Threat Intelligence** is an AI-powered cybersecurity threat news platform. In one sentence: it **aggregates security RSS feeds**, **scrapes and summarizes articles with an LLM**, **maps them to MITRE ATT&CK**, and exposes **search, trends, forecasts, and RAG chat** over a local SQLite database.

### Core pipeline (every ~30 min or on demand)

```
RSS/Atom (61 feeds) + optional Malpedia
    → LLM relevance filter
    → Scrape HTML (trafilatura)
    → Cost estimate + user approval
    → AI summary (exec overview, novelty, mitigations, tags, attack-flow JSON)
    → Optional email notification
    → Embeddings (OpenAI text-embedding-3-small)
    → Dashboard / semantic search / intelligence chat / trend forecasts
```

### Main capabilities

- **Feed aggregation** — 61 pre-configured security feeds; LLM filters noise
- **AI summarization** — OpenAI or Anthropic; prompt caching for cost control
- **MITRE ATT&CK** — Tags, categorization (9 threat categories), kill-chain visualization
- **RAG intelligence** — Natural-language Q&A over your article DB with citations
- **Trend analysis & forecasting** — Category-level historical and 3–6 month forecasts
- **Email** — Per-article or digest (SMTP, stdlib only)
- **Web UI** — Flask + vanilla JS, dark theme, port 5000 (auto-increments if busy)

### Tech stack

| Layer | Technology |
|-------|------------|
| Web | Flask, Jinja2 templates |
| DB | SQLite (WAL), `data/threatlandscape.db` |
| Scheduler | APScheduler |
| LLM | OpenAI / Anthropic via `llm_client.py` |
| Vectors | numpy cosine similarity on 1536-dim embeddings |
| Scraping | trafilatura, feedparser |

### Key files

```
EmergingJoes/
  app.py              # Flask server + REST API
  scheduler.py        # Background pipeline
  feed_fetcher.py     # RSS ingestion
  summarizer.py       # LLM summaries + insights
  intelligence.py     # RAG chat
  embeddings.py       # Vector search
  data/
    config.json       # Runtime config (created on first run)
    config.json.example  # Default 61 feeds
```

---

## What was done on this machine

1. **Cloned** repository to `/Users/diogomachado/projects/emergingJoes/EmergingJoes`
2. **Python 3.12.7** — meets requirement (3.10+)
3. **Virtual environment** at `EmergingJoes/venv/`
4. **Dependencies** installed from `requirements.txt` (Flask, OpenAI, Anthropic, trafilatura, numpy, etc.)
5. **`.env`** created from `.env.example` (edit with your keys)
6. **Verified:**
   - All module imports succeed
   - `init_db()` creates SQLite schema
   - Server runs at `http://127.0.0.1:5050` (test run)
   - `GET /api/stats` → 61 sources, 0 articles (fresh DB)
   - `GET /` → HTTP 200

---

## How to run (no Docker)

```bash
cd /Users/diogomachado/projects/emergingJoes/EmergingJoes
source venv/bin/activate
python app.py
```

Or use the helper script:

```bash
./run.sh
```

Default URL: **http://127.0.0.1:5000** (or next free port). Browser opens automatically on macOS/Linux when `HOST=127.0.0.1`.

### Required for full functionality

| Feature | Requirement |
|---------|-------------|
| Summarization | `OPENAI_API_KEY` **or** `ANTHROPIC_API_KEY` in `.env` or Settings UI |
| Semantic search / RAG | **OpenAI key required** (embeddings always use OpenAI) |
| Malpedia research ingest | Optional `MALPEDIA_API_KEY` |
| Email alerts | Optional SMTP vars in `.env` |

Set keys in **Settings** in the UI or edit `EmergingJoes/.env` and restart.

---

## Current blocker for “full” run

Without valid API keys, the app **runs and serves the UI**, but the pipeline will not summarize or embed articles. Add keys before triggering **Refresh** on the dashboard.

---

## Suggested next steps (adaptation)

1. Add real API keys and run one manual **Refresh** to validate end-to-end pipeline
2. Decide adaptation goals (feeds, auth, deployment target)

---

## References

- App README: `EmergingJoes/README.md`
- Architecture: `EmergingJoes/docs/architecture.md`
- Docs site config: `EmergingJoes/mkdocs.yml` (build locally with `mkdocs serve`)
