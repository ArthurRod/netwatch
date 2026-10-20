#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/netwatch-app"
VENV_DIR="$APP_DIR/venv"
XCB_LIBS=(libxcb-cursor.so.0 libxcb-icccm.so.4 libxcb-keysyms.so.1)
XCB_PACKAGES="libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1"

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
    echo "NetWatch precisa de Python 3.12 ou superior (encontrado: $(python3 --version 2>&1))." >&2
    exit 1
fi

if ! python3 -c 'import ensurepip, venv' 2>/dev/null; then
    echo "Falta o módulo venv do Python. Instale com:" >&2
    echo "  sudo apt install python3-venv" >&2
    exit 1
fi

if ! command -v ss >/dev/null; then
    echo "Aviso: 'ss' não encontrado (pacote iproute2); os bytes por processo ficarão indisponíveis." >&2
fi

echo "Instalando em $APP_DIR"
mkdir -p "$APP_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet --upgrade "$REPO_DIR"

menu_entry="$("$VENV_DIR/bin/python" -c 'from netwatch.services.desktop_entries import install_menu_entry; print(install_menu_entry())')"
echo "Atalho criado: $menu_entry"

autostart_entry="$("$VENV_DIR/bin/python" -c 'from netwatch.services.desktop_entries import autostart_path, is_enabled, set_enabled
if is_enabled():
    set_enabled(True)
    print(autostart_path())')"
if [[ -n "$autostart_entry" ]]; then
    echo "Início automático atualizado: $autostart_entry"
fi

if command -v update-desktop-database >/dev/null; then
    update-desktop-database "$(dirname "$menu_entry")" 2>/dev/null || true
fi

missing=()
for lib in "${XCB_LIBS[@]}"; do
    ldconfig -p | grep -q "$lib" || missing+=("$lib")
done
if [[ "${XDG_SESSION_TYPE:-}" == "wayland" && ${#missing[@]} -gt 0 ]]; then
    echo
    echo "Para o widget ficar sempre visível no Wayland, instale:"
    echo "  sudo apt install $XCB_PACKAGES"
fi

echo
echo "Pronto. Abra o NetWatch pelo menu de aplicativos ou com:"
echo "  $VENV_DIR/bin/netwatch"
