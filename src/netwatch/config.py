import json
import logging
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

logger = logging.getLogger(__name__)

MIN_INTERVAL_MS = 500
MAX_INTERVAL_MS = 10_000
MIN_OPACITY = 0.3
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 365


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "netwatch"


@dataclass(slots=True)
class Settings:
    interval_ms: int = 1000
    opacity: float = 0.92
    always_on_top: bool = True
    prefer_xwayland: bool = True
    history_enabled: bool = True
    history_retention_days: int = 30
    trusted_processes: list[str] = field(default_factory=list)
    resolve_names: bool = True
    window_x: int | None = None
    window_y: int | None = None

    def normalized(self) -> "Settings":
        return Settings(
            interval_ms=min(max(int(self.interval_ms), MIN_INTERVAL_MS), MAX_INTERVAL_MS),
            opacity=min(max(float(self.opacity), MIN_OPACITY), 1.0),
            always_on_top=bool(self.always_on_top),
            prefer_xwayland=bool(self.prefer_xwayland),
            history_enabled=bool(self.history_enabled),
            history_retention_days=min(
                max(int(self.history_retention_days), MIN_RETENTION_DAYS), MAX_RETENTION_DAYS
            ),
            trusted_processes=sorted(
                {key for key in self.trusted_processes if isinstance(key, str)}
                if isinstance(self.trusted_processes, list)
                else set()
            ),
            resolve_names=bool(self.resolve_names),
            window_x=self.window_x if isinstance(self.window_x, int) else None,
            window_y=self.window_y if isinstance(self.window_y, int) else None,
        )


class SettingsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config_dir() / "config.json"

    def load(self) -> Settings:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return Settings()
        except (OSError, json.JSONDecodeError):
            logger.warning("Invalid settings file at %s, using defaults", self.path)
            return Settings()
        if not isinstance(data, dict):
            return Settings()
        known = {f.name for f in fields(Settings)}
        try:
            return Settings(**{k: v for k, v in data.items() if k in known}).normalized()
        except (TypeError, ValueError):
            logger.warning("Invalid settings values at %s, using defaults", self.path)
            return Settings()

    def save(self, settings: Settings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(asdict(settings.normalized()), file, indent=2)
        os.replace(temporary, self.path)
