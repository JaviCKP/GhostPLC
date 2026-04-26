#!/usr/bin/env bash
set -euo pipefail

NETWORK="${GCP_NETWORK:-default}"
TARGET_TAG="${GHOSTPLC_TARGET_TAG:-ghostplc-sensor}"
ADMIN_CIDR="${ADMIN_CIDR:-}"

if [[ -z "$ADMIN_CIDR" ]]; then
  echo "Set ADMIN_CIDR first, for example: ADMIN_CIDR=203.0.113.10/32 $0"
  exit 1
fi

ensure_rule() {
  local name="$1"
  shift

  if gcloud compute firewall-rules describe "$name" >/dev/null 2>&1; then
    echo "Firewall rule exists: $name"
    return
  fi

  gcloud compute firewall-rules create "$name" "$@"
}

ensure_rule ghostplc-allow-admin \
  --network "$NETWORK" \
  --direction INGRESS \
  --priority 1000 \
  --action ALLOW \
  --rules tcp:22,tcp:50022 \
  --source-ranges "$ADMIN_CIDR" \
  --target-tags "$TARGET_TAG" \
  --description "GhostPLC administrative SSH"

ensure_rule ghostplc-allow-honeypots \
  --network "$NETWORK" \
  --direction INGRESS \
  --priority 1000 \
  --action ALLOW \
  --rules tcp:80,tcp:102,tcp:502,tcp:2222,tcp:2223,tcp:8088,udp:161 \
  --source-ranges 0.0.0.0/0 \
  --target-tags "$TARGET_TAG" \
  --description "GhostPLC honeypots and sensor API"

echo "Attach network tag '${TARGET_TAG}' to the VM if it is not already present."

