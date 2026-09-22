# JOES Threat Intelligence

Operational cyber threat intelligence for security analysts. It ingests security
news and research, summarizes it with an LLM, maps each item against your
customers' real technology footprint, and turns the relevant hits into
customer-ready PDF advisories that can be distributed to Slack.

Built on [EmergingJoes](https://github.com/) and styled to match **JOES AIR**, so
the two sit side by side as one product family.

---

## Contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [LLM provider](#1-llm-provider-required)
  - [Getting an OpenRouter API key](#getting-an-openrouter-api-key)
  - [Configuring the Slack token](#2-slack-advisory-distribution)
  - [MISP](#3-misp-optional)
  - [Email digests](#4-email-notifications-optional)
- [Daily workflow](#daily-workflow)
- [Repository layout](#repository-layout)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## What it does

| Page | Purpose |
|------|---------|
| **Feed** | Articles ingested from ~60 RSS/Atom security sources, grouped by category with LLM summaries, key points and tags. |
| **Intelligence** | Semantic search and RAG chat across the whole corpus using embeddings. |
| **Emerging Threats** | The analyst workspace, split into three tabs (below). |
| **Feeds** | Raw ingestion view — every article, its source, and whether scraping succeeded. |
| **Customers** | Customer profiles: country, business, known affiliates, and technology stack. |
| **APT** | Consolidated APT/threat-actor view with IOC extraction and MISP export. |
| **Settings** | LLM provider, Slack, MISP, email, and feed management. |

### The Emerging Threats workspace

- **Threat Intelligence** — articles matched to a customer by technology,
  country, business sector, or named affiliate. Each hit carries an LLM
  explanation of *why it matched* and an adversary-movement outlook, grounded in
  the actual matched values. Analysts triage each item (`pending` → `triaged`).
- **Vulnerabilities** — CVEs matched against customer technology stacks, with
  the same triage queue.
- **Advisories** — every generated advisory, its PDF, and its Slack
  distribution history.

### Advisories

From any triaged hit an analyst can generate an advisory: the LLM drafts
markdown, [Scriba](#repository-layout) renders it to a branded PDF, and the
record is tracked in SQLite. Advisories can then be pushed to chosen Slack
channels, where the PDF is uploaded with a message following a fixed,
business-approved notification template.

---

## How it works

```
RSS / Atom / Malpedia
        │
        ▼
   fetch  ──►  scrape  ──►  cost gate  ──►  summarize  ──►  embed
                                │              │
                                │              ├─► customer TI matching
                                │              └─► CVE + tech-stack matching
                                ▼
                         analyst triage queues
                                │
                                ▼
                    LLM advisory draft ──► Scriba PDF
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
              Slack channels          MISP IOC export
```

The pipeline runs on a schedule (APScheduler, default every 30 minutes) and can
be triggered manually from the UI. The **cost gate** estimates token spend
before summarizing and asks for confirmation, so a large backlog cannot quietly
run up a bill.

Matching is deterministic, not LLM-guessed: `tech_matching.py` applies
word-boundary matching with filtering for generic terms, product-category
acronyms and broad vendor names, to keep false positives down. The LLM is only
asked to *explain* matches it is given, never to invent them.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **Python 3.10+** | Tested on 3.14. Standard-library `venv` is sufficient. |
| **An LLM API key** | OpenAI **or** Anthropic **or** OpenRouter. Required for summarization, matching explanations, advisories and chat. |
| **OpenAI key (situational)** | Only needed if your provider is Anthropic or OpenRouter, which have no embeddings endpoint. Without it those two lose semantic search, RAG chat and digest clustering. OpenAI and Gemini embed with their own key. |
| **Pango / Cairo** | Needed by WeasyPrint for advisory PDFs. Bundled on Windows wheels; on Linux install `libpango-1.0-0 libpangoft2-1.0-0 libcairo2`, on macOS `brew install pango cairo`. |
| **Docker** | Optional — only to run a local MISP instance from `misp/`. |
| **Slack workspace** | Optional — only for advisory distribution. |

Python dependencies are declared in `EmergingJoes/requirements.txt` (Flask,
APScheduler, feedparser, newspaper3k, slack_sdk, pymisp, …) and
`scriba/requirements.txt` (WeasyPrint, Markdown). The installer handles both.

---

## Installation

`start.py` at the repository root is the single entry point. From a fresh clone
it creates both virtual environments, installs their dependencies, seeds config
files from the checked-in examples, and starts the app. It uses only the
standard library, so it runs before anything is installed.

```bash
git clone https://github.com/diog0machad0/EmergingThreats.git
cd EmergingThreats

python start.py          # any platform
./start.sh               # macOS / Linux wrapper
start.bat                # Windows wrapper (double-clickable)
```

A browser opens automatically and the console prints the URL. First run takes a
few minutes while dependencies download; later runs start in seconds, because
each environment records a fingerprint of its `requirements.txt` and skips `pip`
when nothing has changed.

| Flag | Effect |
|------|--------|
| `--setup-only` | Provision environments and config, then exit without serving. |
| `--reinstall` | Reinstall dependencies even if they look current. |
| `--host` / `--port` | Override the bind address and port. |
| `--skip-scriba` | Skip the PDF renderer environment (advisory PDFs will not work). |

The listen address comes from `HOST` / `PORT` in `EmergingJoes/.env`, falling back
to `127.0.0.1` on a free port.

**After the first launch, open Settings and add an LLM API key** — the app starts
and browses fine without one, but nothing will be summarized.

### Manual installation

If you would rather drive each piece yourself, see
[`INSTALL.md`](INSTALL.md). In short:

```bash
cd EmergingJoes
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

---

## Configuration

Two layers, both optional to edit by hand:

| Layer | File | Notes |
|-------|------|-------|
| Environment | `EmergingJoes/.env` | Secrets and bind address. Created from `.env.example` on first run. Git-ignored. |
| Runtime | `EmergingJoes/data/config.json` | Everything editable in **Settings**, including feeds. Created from `config.json.example` on first run. Git-ignored. |

Environment variables win over `config.json`, so a value set in `.env` cannot be
overridden from the UI. For day-to-day use, prefer **Settings**.

### 1. LLM provider (required)

Go to **Settings → LLM Provider** and pick one of OpenAI, Anthropic, OpenRouter
or Gemini, then paste the matching key and press **Test**.

| Provider | Default model | Notes |
|----------|---------------|-------|
| OpenAI | `gpt-4.1-mini` | Fastest path; also covers embeddings. |
| Anthropic | `claude-haiku-4-5` | Chat only — embeddings still need an OpenAI key. |
| OpenRouter | `google/gemma-4-31b-it:free` | Free models available; see limits below. |
| Gemini | `gemini-flash-lite-latest` | Free tier, no billing account, and covers embeddings too. |

> **Pin a concrete model.** Avoid OpenRouter's `openrouter/free` router alias: it
> picks an arbitrary free model per call, and models differ in whether they
> support JSON-mode responses, which breaks structured output mid-pipeline.

#### Getting an OpenRouter API key

OpenRouter is the cheapest way to run this as a proof of concept, because
several capable models are available at no cost.

1. Go to **https://openrouter.ai** and sign in (Google, GitHub or email).
2. Open **https://openrouter.ai/keys** — or click your avatar → **Keys**.
3. Click **Create Key**, give it a name such as `joes-ti`, and leave the credit
   limit blank for free models.
4. Copy the key immediately — it starts with `sk-or-v1-` and is shown only once.
5. In the app: **Settings → LLM Provider → OpenRouter**, paste the key into
   **OpenRouter API Key**, click **Test**, then **Save Settings**.
6. Leave **Model** at `google/gemma-4-31b-it:free`, or browse
   **https://openrouter.ai/models?max_price=0** and pick another `:free` model.

**Free-tier limits.** Free models (`:free` suffix) are capped at **20 requests
per minute** and **50 requests per UTC day** while your account has purchased
under $10 in lifetime credits. Buying $10 of credits once raises the daily cap to
**1,000 requests per day**. Some things worth knowing:

- The daily quota is shared across *all* free models on the account, and is
  tracked per **account**, not per key — extra keys do not help.
- **Failed attempts still count** toward the quota.
- It resets at **UTC midnight**.
- Exhausting it returns HTTP 429. The app recognises quota and auth errors and
  stops retrying rather than mistaking them for a model capability problem.

50 requests/day is enough to explore the UI, but a single full pipeline run over
a day of feeds will exceed it. For real use, either buy the $10 of credits or use
an OpenAI key.

#### Getting a Gemini API key

Gemini is the other no-cost option, and its free daily allowance is considerably
more generous than OpenRouter's. It needs no billing account and no extra Python
package: the app talks to Google's OpenAI-compatible endpoint
(`https://generativelanguage.googleapis.com/v1beta/openai/`) through the OpenAI
client that is already installed.

1. Go to **https://aistudio.google.com/apikey** and sign in with a Google account.
2. Click **Create API key** and pick (or let it create) a project.
3. Copy the key. It starts with `AIza`.
4. In the app: **Settings → LLM Provider → Gemini**, paste the key into
   **Gemini API Key**, click **Test**, then **Save Settings**.

**Choosing a model.** Only Flash and Flash-Lite are on the free tier; the Pro
models now require billing. Flash-Lite carries the largest free daily request
allowance, which is what a full feed run needs.

The dropdown is populated from your key rather than hardcoded, so it only lists
models your account can reach. Use the **Load** button to refresh it. Be aware
that Google keeps retired models in the listing: `gemini-2.5-flash-lite` is
still advertised but returns `404 no longer available to new users` when called.
Listing is therefore not proof of availability, which is why **Test** runs a real
completion against the model you picked.

The default is `gemini-flash-lite-latest`, an alias rather than a pinned version,
so it keeps working as Google rotates concrete ids underneath it.

Measured on this pipeline's JSON summarization prompt, all of these work:

| Model | Round trip |
|-------|-----------|
| `gemini-3.5-flash-lite` | ~1.2 s |
| `gemini-flash-lite-latest` | ~1.9 s |
| `gemini-3.1-flash-lite` | ~3.0 s |
| `gemini-3.5-flash` | ~8.3 s |
| `gemini-flash-latest` | ~40 s, and returned 503 under load |

**Thinking budgets.** This pipeline leans heavily on JSON-mode responses, and
Gemini's thinking tokens count against the output limit, so an unbounded
thinking budget truncates the JSON mid-object. The app sets `reasoning_effort`
to `none` on 2.5 models, where reasoning can be switched off outright, and to
`low` elsewhere with double the output allowance, since 3.x only allows turning
it down.

**Free-tier limits.** Google no longer publishes a fixed table and adjusts quotas
without notice. Independent trackers put Flash-Lite at roughly 15 requests per
minute with a daily cap in the hundreds to low thousands. Quotas are tracked per
**project**, so extra keys in the same project do not raise them, and they reset
at midnight Pacific. Check your live numbers in AI Studio before a large backfill.

**Embeddings are included.** Gemini embeds with `gemini-embedding-001` on the
same key and the same endpoint, so semantic search, RAG chat and digest story
clustering all work without an OpenAI key. Gemini is therefore free end to end.

### 2. Slack advisory distribution

Advisory PDFs are **uploaded as attachments**, not linked — the app serves PDFs
only on localhost, so a download link would be dead for everyone else in the
channel.

#### Which token do I need?

Either works, and both go in the same field:

| Token | Prefix | Posts as | When to use |
|-------|--------|----------|-------------|
| **Bot token** | `xoxb-` | The app ("JOES Threat Intelligence") | Recommended for shared/team use. |
| **User token** | `xoxp-` | **You**, personally | Fine for a PoC, or when you cannot get a bot added to channels. |

Both need the same four scopes:

```
chat:write      post messages
files:write     upload the advisory PDF
channels:read   list public channels
groups:read     list private channels
```

The difference is *where* you add them: a bot token takes them under **Bot Token
Scopes**, a user token under **User Token Scopes**. This is the single most
common mistake — adding scopes to the wrong section leaves the token valid but
unable to list channels or upload.

#### Creating the token

1. Go to **https://api.slack.com/apps** and click **Create New App** →
   **From scratch**. Name it (e.g. `JOES Threat Intelligence`) and select your
   workspace.
2. In the sidebar, open **OAuth & Permissions**.
3. Scroll to **Scopes** and add the four scopes above:
   - for a **bot** token → under **Bot Token Scopes**
   - for a **user** token → under **User Token Scopes**
4. Scroll back up and click **Install to Workspace**, then **Allow**.
   Workspaces with restricted app installation may require admin approval here.
5. Copy the token from the top of the page:
   - **Bot User OAuth Token** → `xoxb-…`
   - **User OAuth Token** → `xoxp-…`

#### Configuring it in the app

1. Open **Settings → Slack Integration**.
2. Turn on **Enable Slack advisory distribution**.
3. Paste the token into **Slack Token**.
4. Click **Test**. It verifies the token you just typed and reports the
   identity and workspace it resolved to.
5. Click **Save Settings**. *Test alone does not save* — the field is
   deliberately tested before storing, so the button checks the typed value
   rather than the stored one.

#### Inviting it to channels

The app only offers channels the token can actually post to, so a channel that
has not been joined will not appear in the picker rather than failing at send
time.

- **Bot token:** invite the app in each target channel with
  `/invite @JOES Threat Intelligence`.
- **User token:** you already have access to every channel you are a member of;
  nothing to invite.

Then, when creating an advisory, pick the channels from the list. Each channel is
attempted independently and its outcome recorded, so one bad channel (archived,
renamed, bot removed) cannot block delivery to the rest.

#### The notification message

Slack messages follow a fixed, business-approved template — an LLM extracts the
field *values* while the layout is rendered in code, so lines cannot be dropped
or renamed. Unknown fields render as `N/A`; the advisory date, attachment list
and remediation deadline are computed in code, never guessed by the model.
Threat-intelligence advisories (no CVE) use a `Threat Intelligence Notification`
variant with the CVE and version lines removed.

See [`EmergingJoes/docs/features/slack-distribution.md`](EmergingJoes/docs/features/slack-distribution.md)
for the full specification.

### 3. MISP (optional)

For exporting APT indicators to a MISP instance.

1. **Settings → MISP Integration** → enable it.
2. Set **MISP URL** (default `https://127.0.0.1:8443`) and your **API key**
   (MISP: *Administration → List Auth Keys → Add authentication key*).
3. Leave **Verify SSL** off for a local instance with a self-signed certificate.

To run MISP locally, `misp/setup.sh` bootstraps a Docker deployment. Exported
events are tagged `source:joes-ti` and linked to the matching Threat Actor
galaxy cluster.

### 4. Email notifications (optional)

**Settings → Email Notifications** takes standard SMTP settings and supports
per-article alerts or a scheduled digest. For Gmail, use an
[App Password](https://support.google.com/accounts/answer/185833), not your
account password.

---

## Daily workflow

1. **Feed** — hit **Refresh** (choose a look-back window, or *Since Last
   Retrieval*). Approve the cost estimate.
2. **Emerging Threats → Threat Intelligence** — work the untriaged queue. Read
   why each item matched, then **Mark as Triaged** or **Open & create advisory**.
3. **Emerging Threats → Vulnerabilities** — same, for CVE matches against
   customer stacks.
4. **Create advisory** — review the draft, generate the PDF, select Slack
   channels, distribute.
5. **APT** — export indicators to MISP where relevant.

Re-running analysis never resets `triage_status`, so already-triaged items stay
triaged.

---

## Repository layout

| Path | Role |
|------|------|
| `start.py`, `start.sh`, `start.bat` | Single entry point — provisions everything and launches. |
| `EmergingJoes/` | The Flask application: UI, REST API, pipeline, SQLite. |
| `EmergingJoes/app.py` | Routes and API endpoints. |
| `EmergingJoes/scheduler.py` | Pipeline orchestration. |
| `EmergingJoes/tech_matching.py` | Canonical customer tech-stack matching. |
| `EmergingJoes/emerging_threats.py`, `vulnerability_threats.py` | Customer TI and CVE matching. |
| `EmergingJoes/advisory_generator.py` | LLM draft → Scriba PDF. |
| `EmergingJoes/advisory_notification.py` | The approved Slack notification template. |
| `EmergingJoes/slack_client.py`, `misp_client.py` | Outbound integrations. |
| `EmergingJoes/docs/` | Full architecture and per-feature documentation. |
| `scriba/` | Markdown → branded PDF renderer (WeasyPrint). |
| `misp/` | Optional local MISP Docker helpers. |
| `INSTALL.md` | Manual, step-by-step install notes. |
| `AGENT_HANDOFF.md` | Engineering conventions and handoff brief. |

Start with [`EmergingJoes/docs/architecture.md`](EmergingJoes/docs/architecture.md)
for the module-by-module tour.

---

## Security notes

This tool handles customer technology inventories and API credentials. Treat the
repository as if it were public.

**Never committed** (enforced by `.gitignore`):

- `EmergingJoes/.env` and `EmergingJoes/data/config.json` — both hold API keys
- `EmergingJoes/data/*.db*` — the SQLite database, including customer profiles
- `export-tvm-*.csv`, `*.xlsx` — customer software/system inventories
- `scriba/reports/*`, `scriba/output/*` — generated advisories, which name
  customers (only `sample_advisory.md`, the LLM's template, is tracked)
- `venv/`, `.venv/`, `__pycache__/`

Also worth knowing:

- The app binds to `127.0.0.1` by default and has **no authentication**. Do not
  expose it on a network interface without putting a reverse proxy and
  authentication in front of it.
- Advisory PDFs are served from localhost only — which is exactly why Slack
  distribution uploads the file rather than linking to it.
- The cross-customer "which other customers are affected" roll-up is shown in
  the UI but deliberately **kept out of Slack messages**: channels are shared,
  and it would leak one customer's exposure to another.

---

## Troubleshooting

**`has_api_key` is false / nothing gets summarized**
Confirm a key is saved in **Settings** and that `EmergingJoes/.env` does not pin a
different `LLM_PROVIDER` — environment variables override the UI. Also make sure
only one instance is running; a stale process on the same port will serve old
configuration.

**HTTP 429 from OpenRouter**
You have hit the free-tier cap (50/day under $10 of lifetime credits). Wait for
UTC midnight, buy $10 of credits for 1,000/day, or switch provider.

**Advisory PDF generation fails**
The Scriba environment is missing or WeasyPrint cannot load Pango/Cairo. Run
`python start.py --setup-only`, and install the system libraries listed under
[Requirements](#requirements).

**Slack test passes but no channels are listed**
The scopes are almost certainly in the wrong section — `channels:read` and
`groups:read` must be under **User Token Scopes** for an `xoxp-` token and
**Bot Token Scopes** for `xoxb-`. If using a bot token, also confirm it has been
invited to the channels.

**Slack token will not save**
**Test** only validates the typed value; you must also click **Save Settings**.

**Some feeds always fail to scrape**
Expected. A few sources (notably GBHackers) return HTTP 403 to non-browser
clients, and a handful of feeds do not parse at all. The **Feeds** page shows
per-article scrape status, and the sidebar surfaces failure counts.

---

## License

Released under the BSD 3-Clause License — see
[`EmergingJoes/LICENSE`](EmergingJoes/LICENSE). This project is a fork, and the
copyright notice in that file must be retained in any redistribution, in source
or binary form.
