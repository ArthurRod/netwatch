import ctypes.util
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import PySide6
from PySide6.QtCore import QPoint, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon

from netwatch.config import Settings, SettingsStore
from netwatch.models.connection import Snapshot
from netwatch.models.signals import Severity
from netwatch.monitoring.signals import untrusted_alerts
from netwatch.services import desktop_entries as autostart
from netwatch.services.history_service import HistoryService
from netwatch.services.monitor_service import MonitorService
from netwatch.storage.database import default_database_path
from netwatch.ui.details_window import DetailsWindow
from netwatch.ui.formatting import format_rate
from netwatch.ui.settings_dialog import SettingsDialog
from netwatch.ui.widget import FloatingWidget

logger = logging.getLogger("netwatch")


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "netwatch"


def setup_logging() -> None:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = RotatingFileHandler(directory / "netwatch.log", maxBytes=1_000_000, backupCount=2)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler, logging.StreamHandler()])


def xcb_plugin_loadable() -> bool:
    plugin = Path(PySide6.__file__).parent / "Qt" / "plugins" / "platforms" / "libqxcb.so"
    try:
        ctypes.CDLL(str(plugin))
    except OSError as error:
        logger.warning("Qt xcb plugin cannot be loaded: %s", error)
        return False
    if ctypes.util.find_library("xcb-cursor") is None:
        logger.warning("libxcb-cursor0 not found")
        return False
    return True


def select_qt_platform(settings: Settings) -> None:
    if "QT_QPA_PLATFORM" in os.environ or not settings.prefer_xwayland:
        return
    if os.environ.get("XDG_SESSION_TYPE") != "wayland" or not os.environ.get("DISPLAY"):
        return
    if not xcb_plugin_loadable():
        logger.warning("Running on native Wayland; always-on-top and saved position unavailable")
        return
    os.environ["QT_QPA_PLATFORM"] = "xcb"


class NetWatchApp:
    def __init__(self, app: QApplication, store: SettingsStore, settings: Settings) -> None:
        self._app = app
        self._store = store
        self._settings = settings
        self._can_position = app.platformName() != "wayland"

        self._history_path = default_database_path()
        self._widget = FloatingWidget(settings.opacity, settings.always_on_top)
        self._history = HistoryService(self._history_path)
        self._details = DetailsWindow(self._history)
        self._monitor = MonitorService(
            settings.interval_ms,
            self._history_path if settings.history_enabled else None,
            settings.history_retention_days,
            settings.resolve_names,
        )
        self._tray = self._build_tray()

        self._save_timer = QTimer(singleShot=True, interval=1000)
        self._save_timer.timeout.connect(self._save_settings)

        self._widget.details_requested.connect(self._show_details)
        self._widget.pause_toggled.connect(self._monitor.toggle_paused)
        self._widget.settings_requested.connect(self._open_settings)
        self._widget.hide_requested.connect(self._hide_widget)
        self._widget.quit_requested.connect(self._app.quit)
        self._widget.position_changed.connect(self._remember_position)
        self._monitor.snapshot_ready.connect(self._on_snapshot)
        self._monitor.failed.connect(self._on_failure)
        self._monitor.history_failed.connect(self._on_history_failure)
        self._widget.alerts_requested.connect(self._show_alerts)
        self._details.alerts.trust_toggled.connect(self._toggle_trust)
        self._notified: dict[str, Severity] = {}
        self._apply_trusted()
        self._monitor.paused_changed.connect(self._on_paused_changed)
        self._app.aboutToQuit.connect(self._shutdown)

    def start(self) -> None:
        if self._can_position and self._settings.window_x is not None and self._settings.window_y is not None:
            self._widget.move(self._settings.window_x, self._settings.window_y)
        self._widget.show()
        self._monitor.start()
        logger.info("NetWatch started on platform %s", self._app.platformName())

    def _build_tray(self) -> QSystemTrayIcon | None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return None
        icon = QIcon.fromTheme("network-transmit-receive", self._app.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon))
        tray = QSystemTrayIcon(icon)
        menu = QMenu()
        toggle = QAction("Mostrar/ocultar widget", menu)
        toggle.triggered.connect(self._toggle_widget)
        details = QAction("Detalhes", menu)
        details.triggered.connect(self._show_details)
        pause = QAction("Pausar/retomar", menu)
        pause.triggered.connect(self._monitor.toggle_paused)
        quit_action = QAction("Sair", menu)
        quit_action.triggered.connect(self._app.quit)
        for action in (toggle, details, pause):
            menu.addAction(action)
        menu.addSeparator()
        menu.addAction(quit_action)
        tray.setContextMenu(menu)
        tray.activated.connect(self._on_tray_activated)
        tray.setToolTip("NetWatch")
        tray.show()
        self._tray_menu = menu
        return tray

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._toggle_widget()

    def _toggle_widget(self) -> None:
        if self._widget.isVisible():
            self._widget.hide()
        else:
            self._widget.show()

    def _hide_widget(self) -> None:
        if self._tray is None:
            self._widget.showMinimized()
            return
        self._widget.hide()

    def _show_details(self) -> None:
        self._details.show()
        self._details.raise_()
        self._details.activateWindow()

    def _show_alerts(self) -> None:
        self._show_details()
        self._details.show_alerts()

    def _apply_trusted(self) -> None:
        trusted = set(self._settings.trusted_processes)
        self._widget.set_trusted(trusted)
        self._details.alerts.set_trusted(trusted)

    def _toggle_trust(self, key: str) -> None:
        trusted = set(self._settings.trusted_processes)
        trusted.symmetric_difference_update({key})
        self._settings.trusted_processes = sorted(trusted)
        self._apply_trusted()
        self._save_settings()

    def _notify_alerts(self, snapshot: Snapshot) -> None:
        if self._tray is None:
            return
        for summary in untrusted_alerts(snapshot.outbound_by_process, set(self._settings.trusted_processes)):
            key = summary.process.group_key
            if summary.severity < Severity.MEDIUM or self._notified.get(key, 0) >= summary.severity:
                continue
            self._notified[key] = summary.severity
            self._tray.showMessage(
                f"NetWatch: {summary.process_name}",
                summary.signals[0].message,
                QSystemTrayIcon.MessageIcon.Warning,
            )

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self._settings, self._app.platformName(), autostart.is_enabled())
        if not dialog.exec():
            return
        self._apply_autostart(dialog.autostart_enabled())
        updated = dialog.result_settings()
        self._widget.set_opacity(updated.opacity)
        if updated.always_on_top != self._settings.always_on_top:
            self._widget.set_always_on_top(updated.always_on_top)
        if updated.interval_ms != self._settings.interval_ms:
            self._monitor.set_interval(updated.interval_ms)
        self._monitor.configure_history(
            self._history_path if updated.history_enabled else None,
            updated.history_retention_days,
        )
        self._monitor.set_resolve_names(updated.resolve_names)
        self._settings = updated
        self._save_settings()

    def _apply_autostart(self, enabled: bool) -> None:
        try:
            autostart.set_enabled(enabled)
        except OSError:
            logger.exception("Could not update autostart entry")

    def _remember_position(self, position: QPoint) -> None:
        if not self._can_position:
            return
        self._settings.window_x = position.x()
        self._settings.window_y = position.y()
        self._save_timer.start()

    def _on_snapshot(self, snapshot: Snapshot) -> None:
        if not self._monitor.is_paused:
            self._widget.set_status("active")
        self._widget.update_snapshot(snapshot)
        self._details.update_snapshot(snapshot)
        self._notify_alerts(snapshot)
        if self._tray is not None:
            self._tray.setToolTip(f"NetWatch — saindo {format_rate(snapshot.traffic.sent_per_second)}")

    def _on_failure(self, message: str) -> None:
        self._widget.set_status("error")
        self._widget.setToolTip(message)

    def _on_history_failure(self, message: str) -> None:
        logger.error("History disabled: %s", message)
        if self._tray is not None:
            self._tray.showMessage("NetWatch", f"Histórico desativado: {message}", QSystemTrayIcon.MessageIcon.Warning)

    def _on_paused_changed(self, paused: bool) -> None:
        self._widget.set_status("paused" if paused else "active")

    def _save_settings(self) -> None:
        try:
            self._store.save(self._settings)
        except OSError:
            logger.exception("Could not save settings to %s", self._store.path)

    def _shutdown(self) -> None:
        self._monitor.shutdown()
        self._history.wait()
        self._save_settings()
        if self._tray is not None:
            self._tray.hide()
        logger.info("NetWatch stopped")


def main() -> None:
    setup_logging()
    store = SettingsStore()
    settings = store.load()
    select_qt_platform(settings)

    app = QApplication(sys.argv)
    app.setApplicationName("NetWatch")
    app.setDesktopFileName("netwatch")
    app.setQuitOnLastWindowClosed(False)

    netwatch = NetWatchApp(app, store, settings)
    netwatch.start()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
