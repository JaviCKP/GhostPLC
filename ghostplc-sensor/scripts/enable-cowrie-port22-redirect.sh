#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if [[ "${GHOSTPLC_ENABLE_PORT22_REDIRECT:-}" != "yes" ]]; then
  echo "Refusing to redirect port 22 without explicit opt-in."
  echo "First move real SSH to a high port, verify login, then run:"
  echo "sudo GHOSTPLC_ENABLE_PORT22_REDIRECT=yes $0"
  exit 1
fi

iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null \
  || iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222

netfilter-persistent save
echo "Inbound TCP/22 now redirects to Cowrie on TCP/2222."

