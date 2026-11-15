#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "✔ .env created from .env.example"
fi
cat <<EOT

Next steps:
  1. Review .env – especially CA_NAME, CA_HOSTNAME, PERMITTED_DOMAINS, ALLOWED_NETWORKS
  2. Create a DNS record for CA_HOSTNAME pointing to this Docker host
  3. docker compose up -d --build
  4. docker compose logs ca      → root fingerprint and URLs
  5. Web UI: https://<CA_HOSTNAME>:8443
  Full guide: docs/installation.md
EOT
