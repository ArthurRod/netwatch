#!/usr/bin/env bash
set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
APP_DIR="$DATA_HOME/netwatch-app"
PURGE=false

for argument in "$@"; do
    case "$argument" in
        --purge) PURGE=true ;;
        *) echo "Uso: $0 [--purge]" >&2; exit 2 ;;
    esac
done

if pgrep -u "$USER" -f "^[^ ]*netwatch-app/venv/bin/(python[0-9.]*|netwatch)( |$)" >/dev/null; then
    echo "Feche o NetWatch antes de desinstalar (ícone da bandeja → Sair)." >&2
    exit 1
fi

remove() {
    if [[ -e "$1" ]]; then
        rm -rf -- "$1"
        echo "Removido: $1"
    fi
}

remove "$DATA_HOME/applications/netwatch.desktop"
remove "$CONFIG_HOME/autostart/netwatch.desktop"
remove "$APP_DIR"

if $PURGE; then
    remove "$CONFIG_HOME/netwatch"
    remove "$DATA_HOME/netwatch"
    remove "$STATE_HOME/netwatch"
else
    echo
    echo "Preferências, histórico e logs foram mantidos. Para apagá-los também:"
    echo "  $0 --purge"
fi
