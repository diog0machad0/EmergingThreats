# Requirements summary

Canonical installable dependency lists:

| Component | File |
|-----------|------|
| EmergingJoes app | [`EmergingJoes/requirements.txt`](EmergingJoes/requirements.txt) |
| Scriba PDF engine | [`scriba/requirements.txt`](scriba/requirements.txt) |

## Runtime requirements

- **Python 3.10+**
- At least one of: OpenAI / Anthropic / OpenRouter API key
- **WeasyPrint OS libraries** (Pango, Cairo, …) only if generating advisory PDFs — see [INSTALL.md](INSTALL.md)
- **Docker** only if self-hosting MISP via `misp/` (optional)

## EmergingJoes Python packages

```
flask>=3.0
feedparser>=6.0
trafilatura>=1.0
newspaper3k>=0.2
openai>=1.0
anthropic>=0.30
apscheduler>=3.10
requests>=2.31
lxml_html_clean
numpy>=1.24
python-dotenv>=1.0
pymisp>=2.4.180
```

## Scriba Python packages

```
jinja2
markdown-it-py
mdit-py-plugins
pyyaml
beautifulsoup4
weasyprint
```

For reproducible deploys, create lockfiles after a clean install:

```bash
cd EmergingJoes && pip freeze > requirements.lock.txt
cd ../scriba && pip freeze > requirements.lock.txt
```
