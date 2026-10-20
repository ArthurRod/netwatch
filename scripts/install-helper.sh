#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR=/usr/local/lib/netwatch-helper
CONFIG=/etc/netwatch-helper.conf
UNIT=/etc/systemd/system/netwatch-helper.service

if [[ $EUID -ne 0 ]]; then
    echo "Rode com sudo: sudo $0" >&2
    exit 1
fi
if [[ -z "${SUDO_UID:-}" || "$SUDO_UID" == "0" ]]; then
    echo "Rode via sudo a partir do seu usuário (não como root direto), para o helper saber quem pode ler os eventos." >&2
    exit 1
fi
if ! command -v bpftrace >/dev/null; then
    echo "Falta o bpftrace. Instale com: sudo apt install bpftrace" >&2
    exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "Aviso: o kernel não expõe BTF (/sys/kernel/btf/vmlinux); o bpftrace pode não conseguir ler as estruturas TCP." >&2
fi

install -d -m 0755 -o root -g root "$LIB_DIR"
install -m 0644 -o root -g root "$REPO_DIR/helper/netwatch_helper.py" "$REPO_DIR/helper/netwatch.bt" "$LIB_DIR/"
printf '{"allowed_uids": [%s]}\n' "$SUDO_UID" > "$CONFIG"
chmod 0644 "$CONFIG"
install -m 0644 -o root -g root "$REPO_DIR/helper/netwatch-helper.service" "$UNIT"

echo "Autoteste (até ~40 s)..."
if ! /usr/bin/python3 -I "$LIB_DIR/netwatch_helper.py" --self-test; then
    echo "Autoteste falhou: o serviço NÃO foi ativado. Os arquivos ficaram instalados para diagnóstico." >&2
    exit 1
fi

systemctl daemon-reload
systemctl enable --now netwatch-helper.service
sleep 2
systemctl --no-pager --lines=5 status netwatch-helper.service || true
echo
echo "Helper ativo. O NetWatch se conecta a ele automaticamente."
