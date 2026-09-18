#!/usr/bin/env bash
# Install and start MISP via the official misp-docker project.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
MISP_DIR="${ROOT}/misp-docker"

if [[ ! -d "$MISP_DIR" ]]; then
  echo "Cloning MISP docker..."
  git clone --depth 1 https://github.com/MISP/misp-docker.git "$MISP_DIR"
fi

cd "$MISP_DIR"

if [[ ! -f .env ]]; then
  echo "Creating .env from template..."
  cp template.env .env
fi

# Local JOES Threat Intelligence defaults
set_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env; then
    sed -i.bak "s|^${key}=.*|${key}=${val}|" .env
  else
    echo "${key}=${val}" >> .env
  fi
}

ADMIN_KEY="${MISP_ADMIN_KEY:-$(openssl rand -hex 20)}"

set_env BASE_URL "https://127.0.0.1:8443"
set_env CORE_HTTPS_PORT "8443"
set_env CORE_HTTP_PORT "8080"
set_env ADMIN_EMAIL "admin@emerging-joes.local"
set_env ADMIN_PASSWORD "Admin1234!"
set_env ADMIN_KEY "$ADMIN_KEY"
set_env ADMIN_ORG "Security Joes"
set_env DISABLE_SSL_REDIRECT "true"
set_env MISP_CONTACT "admin@emerging-joes.local"
set_env MISP_EMAIL "admin@emerging-joes.local"

echo ""
echo "Starting MISP (first boot may take several minutes)..."
docker compose up -d

echo "Waiting for MISP core to accept console commands..."
for i in $(seq 1 60); do
  if docker compose exec -T misp-core sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting MISP.live true >/dev/null 2>&1; then
    echo "MISP.live enabled."
    break
  fi
  if [[ $i -eq 60 ]]; then
    echo "Could not enable MISP.live yet — run: ./enable-live.sh"
  fi
  sleep 10
done

echo ""
echo "============================================"
echo "MISP URL:      https://127.0.0.1:8443"
echo "Admin email:   admin@emerging-joes.local"
echo "Admin pass:    Admin1234!"
echo "API key:       ${ADMIN_KEY}"
echo ""
echo "Add the API key to JOES Threat Intelligence Settings → MISP"
echo "============================================"

# Write key hint for EmergingJoes config (user still confirms in Settings)
TL_CONFIG="../EmergingJoes/data/config.json"
if [[ -f "$TL_CONFIG" ]]; then
  python3 - <<PY
import json
from pathlib import Path
p = Path("${TL_CONFIG}")
cfg = json.loads(p.read_text())
cfg.setdefault("misp_url", "https://127.0.0.1:8443")
cfg.setdefault("misp_enabled", True)
cfg.setdefault("misp_verify_ssl", False)
if not cfg.get("misp_api_key"):
    cfg["misp_api_key"] = "${ADMIN_KEY}"
p.write_text(json.dumps(cfg, indent=2) + "\n")
print("Updated EmergingJoes/data/config.json with MISP URL and API key")
PY
fi
