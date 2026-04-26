#!/usr/bin/env bash
set -euo pipefail

TCP_PORTS=(80 102 502 2222 2223 8088 50022)
UDP_PORTS=(161)

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent

for port in "${TCP_PORTS[@]}"; do
  iptables -C INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT
done

for port in "${UDP_PORTS[@]}"; do
  iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT -p udp --dport "$port" -j ACCEPT
done

netfilter-persistent save
echo "Linux firewall updated for GhostPLC ports."

