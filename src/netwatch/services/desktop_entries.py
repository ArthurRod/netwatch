import os
import sys
from pathlib import Path

FILE_NAME = "netwatch.desktop"
RESERVED = ('\\', '"', "`", "$")

MENU_TEMPLATE = """[Desktop Entry]
Type=Application
Name=NetWatch
Comment=Resumo do tráfego de rede que sai do computador
Exec={exec}
Icon=network-transmit-receive
Terminal=false
Categories=Network;Monitor;
StartupWMClass=netwatch
"""

AUTOSTART_EXTRA = """X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
"""


def autostart_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autostart" / FILE_NAME


def menu_entry_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "applications" / FILE_NAME


def render(autostart: bool = False) -> str:
    content = MENU_TEMPLATE.format(exec=launch_command())
    return content + AUTOSTART_EXTRA if autostart else content


def install_menu_entry(path: Path | None = None) -> Path:
    target = path or menu_entry_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(), encoding="utf-8")
    return target


def quote_exec_argument(argument: str) -> str:
    if not argument or any(char in argument for char in ' \t\n"\'\\><~|&;$*?#()`='):
        escaped = "".join(f"\\{char}" if char in RESERVED else char for char in argument)
        return f'"{escaped}"'
    return argument


def launch_command() -> str:
    return " ".join(quote_exec_argument(argument) for argument in (sys.executable, "-m", "netwatch"))


def is_enabled(path: Path | None = None) -> bool:
    return (path or autostart_path()).exists()


def set_enabled(enabled: bool, path: Path | None = None) -> None:
    target = path or autostart_path()
    if not enabled:
        target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(autostart=True), encoding="utf-8")
