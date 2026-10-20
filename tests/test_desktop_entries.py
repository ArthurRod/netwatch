import shutil
import subprocess

import pytest

from netwatch.services import desktop_entries as autostart


def test_enable_and_disable(tmp_path, monkeypatch):
    monkeypatch.setattr(autostart.sys, "executable", "/opt/my apps/venv/bin/python")
    path = tmp_path / "autostart" / "netwatch.desktop"
    assert not autostart.is_enabled(path)
    autostart.set_enabled(True, path)
    content = path.read_text()
    assert 'Exec="/opt/my apps/venv/bin/python" -m netwatch' in content
    assert autostart.is_enabled(path)
    autostart.set_enabled(False, path)
    autostart.set_enabled(False, path)
    assert not autostart.is_enabled(path)


def test_exec_quoting_follows_desktop_spec():
    assert autostart.quote_exec_argument("/usr/bin/python3") == "/usr/bin/python3"
    assert autostart.quote_exec_argument("/a b/py") == '"/a b/py"'
    assert autostart.quote_exec_argument('/a"$b/py') == '"/a\\"\\$b/py"'


@pytest.mark.skipif(shutil.which("desktop-file-validate") is None, reason="desktop-file-validate not installed")
def test_generated_file_is_valid(tmp_path):
    path = tmp_path / "netwatch.desktop"
    autostart.set_enabled(True, path)
    result = subprocess.run(["desktop-file-validate", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(shutil.which("desktop-file-validate") is None, reason="desktop-file-validate not installed")
def test_menu_entry_is_valid_and_has_no_autostart_keys(tmp_path):
    path = autostart.install_menu_entry(tmp_path / "applications" / "netwatch.desktop")
    content = path.read_text()
    assert "X-GNOME-Autostart" not in content
    result = subprocess.run(["desktop-file-validate", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
