#!/usr/bin/env bash
# Enable MISP.live (required for API/UI access after fresh install).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${ROOT}/misp-docker"

echo "Enabling MISP.live..."
docker compose exec -T misp-core sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting MISP.live true
echo "Done. Refresh https://127.0.0.1:8443"
