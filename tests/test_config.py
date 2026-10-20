import json
import stat

from netwatch.config import Settings, SettingsStore


def test_missing_file_returns_defaults(tmp_path):
    assert SettingsStore(tmp_path / "config.json").load() == Settings()


def test_roundtrip_with_restricted_permissions(tmp_path):
    store = SettingsStore(tmp_path / "netwatch" / "config.json")
    store.save(Settings(opacity=0.5, window_x=10, window_y=20))
    assert store.load() == Settings(opacity=0.5, window_x=10, window_y=20)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700


def test_invalid_and_out_of_range_values_are_normalized(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"opacity": 5, "interval_ms": 1, "window_x": "a", "unknown": True}))
    settings = SettingsStore(path).load()
    assert settings.opacity == 1.0
    assert settings.interval_ms == 500
    assert settings.window_x is None


def test_corrupted_file_returns_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json")
    assert SettingsStore(path).load() == Settings()
