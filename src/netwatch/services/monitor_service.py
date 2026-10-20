import logging
import sqlite3
from pathlib import Path
from time import time

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot

from netwatch.models.connection import Snapshot
from netwatch.models.process import ProcessIdentity
from netwatch.monitoring.collector import SnapshotBuilder
from netwatch.monitoring.signals import SignalDetector
from netwatch.services.domain_resolver import DomainResolver
from netwatch.storage.history import HistoryRecorder

logger = logging.getLogger(__name__)

SUSPEND_GAP_FACTOR = 5


class _Worker(QObject):
    snapshot_ready = Signal(object)
    failed = Signal(str)
    history_failed = Signal(str)

    def __init__(self, interval_ms: int, history_path: Path | None, retention_days: int, resolve_names: bool) -> None:
        super().__init__()
        self._interval_ms = interval_ms
        self._resolve_names = resolve_names
        self._history_path = history_path
        self._retention_days = retention_days
        self._recorder: HistoryRecorder | None = None
        self._builder: SnapshotBuilder | None = None
        self._timer: QTimer | None = None
        self._last_tick_ms: int | None = None

    @Slot()
    def start(self) -> None:
        self._open_history()
        self._builder = SnapshotBuilder(resolver=DomainResolver() if self._resolve_names else None)
        self._detector = SignalDetector(self._is_known, self._learning_until)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(self._interval_ms)
        self._tick()

    @Slot()
    def stop(self) -> None:
        if self._timer is not None:
            self._timer.stop()
        if self._builder is not None:
            self._builder.close()
        self._close_history()

    @Slot(bool)
    def set_resolve_names(self, enabled: bool) -> None:
        if enabled == self._resolve_names:
            return
        self._resolve_names = enabled
        if self._builder is not None:
            self._builder.set_resolver(DomainResolver() if enabled else None)

    @Slot(object, int)
    def configure_history(self, path: Path | None, retention_days: int) -> None:
        self._retention_days = retention_days
        if path != self._history_path:
            self._close_history()
            self._history_path = path
            self._open_history()
        elif self._recorder is not None:
            self._recorder.set_retention_days(retention_days)

    def _open_history(self) -> None:
        if self._history_path is None or self._recorder is not None:
            return
        try:
            self._recorder = HistoryRecorder(self._history_path, self._retention_days)
        except (sqlite3.Error, OSError) as error:
            logger.exception("Could not open history database")
            self.history_failed.emit(str(error))

    def _close_history(self) -> None:
        if self._recorder is None:
            return
        try:
            self._recorder.close()
        except (sqlite3.Error, OSError):
            logger.exception("Could not close history database")
        self._recorder = None

    def _is_known(self, process: ProcessIdentity) -> bool | None:
        if self._recorder is None:
            return None
        try:
            return self._recorder.seen_before_session(process.label, process.exe)
        except sqlite3.Error:
            logger.exception("History lookup failed")
            return None

    def _learning_until(self) -> float | None:
        return self._recorder.learning_until() if self._recorder is not None else None

    def _record(self, snapshot: Snapshot) -> None:
        if self._recorder is None:
            return
        try:
            self._recorder.record(snapshot)
        except (sqlite3.Error, OSError) as error:
            logger.exception("History write failed; disabling history")
            self.history_failed.emit(str(error))
            self._close_history()

    @Slot(bool)
    def set_paused(self, paused: bool) -> None:
        if self._timer is None or self._builder is None:
            return
        if paused:
            self._timer.stop()
            return
        self._builder.reset_rates()
        self._last_tick_ms = None
        self._timer.start(self._interval_ms)
        self._tick()

    @Slot(int)
    def set_interval(self, interval_ms: int) -> None:
        self._interval_ms = interval_ms
        if self._timer is not None and self._timer.isActive():
            self._timer.start(interval_ms)

    @Slot()
    def _tick(self) -> None:
        if self._builder is None:
            return
        self._reset_rates_after_suspend()
        try:
            snapshot = self._detector.apply(self._builder.build())
        except Exception as error:
            logger.exception("Snapshot collection failed")
            self.failed.emit(str(error))
            return
        self._record(snapshot)
        self.snapshot_ready.emit(snapshot)

    def _reset_rates_after_suspend(self) -> None:
        now_ms = int(time() * 1000)
        if self._last_tick_ms is not None and now_ms - self._last_tick_ms > self._interval_ms * SUSPEND_GAP_FACTOR:
            self._builder.reset_rates()
        self._last_tick_ms = now_ms


class MonitorService(QObject):
    snapshot_ready = Signal(Snapshot)
    failed = Signal(str)
    history_failed = Signal(str)
    paused_changed = Signal(bool)

    _request_start = Signal()
    _request_stop = Signal()
    _request_pause = Signal(bool)
    _request_interval = Signal(int)
    _request_history = Signal(object, int)
    _request_resolve_names = Signal(bool)

    def __init__(
        self,
        interval_ms: int,
        history_path: Path | None,
        retention_days: int,
        resolve_names: bool,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._paused = False
        self._thread = QThread()
        self._thread.setObjectName("netwatch-monitor")
        self._worker = _Worker(interval_ms, history_path, retention_days, resolve_names)
        self._worker.moveToThread(self._thread)
        self._thread.finished.connect(self._worker.deleteLater)

        self._worker.snapshot_ready.connect(self.snapshot_ready)
        self._worker.failed.connect(self.failed)
        self._worker.history_failed.connect(self.history_failed)
        self._request_start.connect(self._worker.start)
        self._request_stop.connect(self._worker.stop, Qt.ConnectionType.BlockingQueuedConnection)
        self._request_history.connect(self._worker.configure_history)
        self._request_resolve_names.connect(self._worker.set_resolve_names)
        self._request_pause.connect(self._worker.set_paused)
        self._request_interval.connect(self._worker.set_interval)

    @property
    def is_paused(self) -> bool:
        return self._paused

    def start(self) -> None:
        self._thread.start()
        self._request_start.emit()

    def set_paused(self, paused: bool) -> None:
        if paused == self._paused:
            return
        self._paused = paused
        self._request_pause.emit(paused)
        self.paused_changed.emit(paused)

    def toggle_paused(self) -> None:
        self.set_paused(not self._paused)

    def set_interval(self, interval_ms: int) -> None:
        self._request_interval.emit(interval_ms)

    def configure_history(self, path: Path | None, retention_days: int) -> None:
        self._request_history.emit(path, retention_days)

    def set_resolve_names(self, enabled: bool) -> None:
        self._request_resolve_names.emit(enabled)

    def shutdown(self) -> None:
        if not self._thread.isRunning():
            return
        self._request_stop.emit()
        self._thread.quit()
        self._thread.wait(3000)
