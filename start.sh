#!/usr/bin/env bash
# Single entry point for JOES Threat Intelligence (macOS/Linux).
# Delegates to start.py, which provisions both virtualenvs and serves the app.
set -euo pipefail
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
  exec python3 start.py "$@"
elif command -v python >/dev/null 2>&1; then
  exec python start.py "$@"
fi

echo "Python not found. Install Python 3.10+ and ensure it is on PATH." >&2
exit 1
