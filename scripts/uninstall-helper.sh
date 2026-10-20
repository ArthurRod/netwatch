#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Rode com sudo: sudo $0" >&2
    exit 1
fi

systemctl disable --now netwatch-helper.service 2>/dev/null || true
rm -f /etc/systemd/system/netwatch-helper.service /etc/netwatch-helper.conf
rm -rf /usr/local/lib/netwatch-helper /run/netwatch-helper
systemctl daemon-reload
echo "Helper removido. O NetWatch continua funcionando sem ele."
