#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

INSTALL_USER="${SUDO_USER:-${USER}}"
INSTALL_GROUP="$(id -gn "$INSTALL_USER")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

render_unit() {
  local source="$1"
  local target="/etc/systemd/system/$(basename "$source")"
  sed \
    -e "s|__GHOSTPLC_USER__|${INSTALL_USER}|g" \
    -e "s|__GHOSTPLC_GROUP__|${INSTALL_GROUP}|g" \
    -e "s|__GHOSTPLC_ROOT__|${PROJECT_ROOT}|g" \
    "$source" > "$target"
}

render_unit "$PROJECT_ROOT/systemd/ghostplc-api.service"
render_unit "$PROJECT_ROOT/systemd/ghostplc-collector.service"
render_unit "$PROJECT_ROOT/systemd/ghostplc-analyzer.service"
cp "$PROJECT_ROOT/systemd/ghostplc-collector.timer" /etc/systemd/system/
cp "$PROJECT_ROOT/systemd/ghostplc-analyzer.timer" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now ghostplc-api.service
systemctl enable --now ghostplc-collector.timer
systemctl enable --now ghostplc-analyzer.timer

echo "Installed GhostPLC systemd units for user ${INSTALL_USER} at ${PROJECT_ROOT}"

