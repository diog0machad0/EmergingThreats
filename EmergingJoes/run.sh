#!/usr/bin/env bash
# Local launcher (macOS/Linux) — no Docker
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -d venv ]]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

source venv/bin/activate

if ! python -c "import flask" 2>/dev/null; then
  echo "Installing dependencies..."
  pip install -r requirements.txt
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example — add your API keys before summarization."
fi

export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-5000}"
echo "Starting JOES Threat Intelligence at http://${HOST}:${PORT}"
exec python app.py
