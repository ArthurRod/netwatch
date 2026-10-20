import logging
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from netwatch.models.history import HistoryQuery
from netwatch.storage.history import HistoryReader

logger = logging.getLogger(__name__)


class _Relay(QObject):
    finished = Signal(int, object)
    failed = Signal(int, str)


class _Task(QRunnable):
    def __init__(self, request_id: int, work: Callable[[], Any], relay: _Relay) -> None:
        super().__init__()
        self._request_id = request_id
        self._work = work
        self._relay = relay

    def run(self) -> None:
        try:
            result = self._work()
        except (sqlite3.Error, OSError) as error:
            logger.exception("History operation failed")
            self._relay.failed.emit(self._request_id, str(error))
            return
        self._relay.finished.emit(self._request_id, result)


class HistoryService(QObject):
    connections_ready = Signal(object)
    processes_ready = Signal(object)
    cleared = Signal()
    failed = Signal(str)

    def __init__(self, path: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._reader = HistoryReader(path)
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(1)
        self._relay = _Relay()
        self._relay.finished.connect(self._on_finished)
        self._relay.failed.connect(self._on_failed)
        self._next_id = 0
        self._latest: dict[str, int] = {}
        self._kinds: dict[int, str] = {}

    def query_connections(self, query: HistoryQuery) -> None:
        self._submit("connections", lambda: self._reader.connections(query))

    def query_processes(self, query: HistoryQuery) -> None:
        self._submit("processes", lambda: self._reader.processes(query))

    def clear(self) -> None:
        self._submit("clear", self._reader.clear)

    def wait(self) -> None:
        self._pool.waitForDone()

    def _submit(self, kind: str, work: Callable[[], Any]) -> None:
        self._next_id += 1
        self._latest[kind] = self._next_id
        self._kinds[self._next_id] = kind
        self._pool.start(_Task(self._next_id, work, self._relay))

    def _on_finished(self, request_id: int, result: object) -> None:
        kind = self._kinds.pop(request_id)
        if self._latest.get(kind) != request_id:
            return
        if kind == "connections":
            self.connections_ready.emit(result)
        elif kind == "processes":
            self.processes_ready.emit(result)
        else:
            self.cleared.emit()

    def _on_failed(self, request_id: int, message: str) -> None:
        self._kinds.pop(request_id, None)
        self.failed.emit(message)
