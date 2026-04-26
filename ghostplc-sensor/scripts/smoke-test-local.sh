#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

echo "== docker compose =="
docker compose ps

echo
echo "== local TCP ports =="
for port in 80 102 502 2222 2223 8088; do
  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
    echo "open tcp/${port}"
  else
    echo "closed tcp/${port}"
  fi
done

echo
echo "== api =="
curl -fsS http://127.0.0.1:8088/health
echo

if [[ -n "${GHOSTPLC_API_TOKEN:-}" ]]; then
  curl -fsS -H "Authorization: Bearer ${GHOSTPLC_API_TOKEN}" \
    "http://127.0.0.1:8088/events.json?limit=5"
  echo
else
  echo "GHOSTPLC_API_TOKEN not set; skipping authenticated events check."
fi

echo
echo "Smoke test complete. Run the external checks from your PC too; local open ports do not prove GCP firewall is open."
