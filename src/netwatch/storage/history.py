import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from netwatch.models.connection import Connection, Protocol, Snapshot
from netwatch.models.domain import RemoteName
from netwatch.models.history import HistoryEntry, HistoryQuery, ProcessHistory
from netwatch.storage.database import open_database

LAST_SEEN_REFRESH_SECONDS = 60
PRUNE_INTERVAL_SECONDS = 3600
LEARNING_SECONDS = 86_400
SECONDS_PER_DAY = 86_400

INSERT = """
INSERT INTO connections (
    first_seen, seen_at_start, last_seen, protocol, local_ip, local_port, remote_ip, remote_port,
    status, pid, process_label, exe, exe_deleted, command, username, lineage, bytes_sent, bytes_received,
    remote_name, remote_name_confirmed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

UPDATE = """
UPDATE connections SET last_seen = ?, status = ?, bytes_sent = ?, bytes_received = ?,
    remote_name = ?, remote_name_confirmed = ? WHERE id = ?
"""

CLOSE = "UPDATE connections SET last_seen = ?, closed_at = ? WHERE id = ?"


@dataclass(slots=True)
class _OpenRow:
    id: int
    status: str | None
    bytes_sent: int | None
    bytes_received: int | None
    remote_name: RemoteName | None
    written_at: float


class HistoryRecorder:
    def __init__(self, path: Path, retention_days: int, clock: Callable[[], float] = time.time) -> None:
        self._db = open_database(path)
        self._retention_days = retention_days
        self._clock = clock
        self._open: dict[tuple, _OpenRow] = {}
        self._previous_time: float | None = None
        self._pruned_at: float | None = None
        self._session_start = clock()
        oldest = self._db.execute("SELECT MIN(first_seen) FROM connections").fetchone()[0]
        self._history_start = oldest if oldest is not None else self._session_start

    def learning_until(self) -> float | None:
        until = self._history_start + LEARNING_SECONDS
        return until if self._clock() < until else None

    def seen_before_session(self, label: str | None, exe: str | None) -> bool | None:
        if self.learning_until() is not None:
            return None
        row = self._db.execute(
            "SELECT 1 FROM connections WHERE process_label IS ? AND exe IS ? AND first_seen < ? LIMIT 1",
            (label, exe, self._session_start),
        ).fetchone()
        return row is not None

    def set_retention_days(self, days: int) -> None:
        self._retention_days = days
        self._pruned_at = None

    def record(self, snapshot: Snapshot) -> None:
        now = snapshot.taken_at.timestamp()
        first_run = self._previous_time is None
        current = {c.key: c for c in snapshot.connections if c.is_outbound}
        with self._db:
            for key, connection in current.items():
                row = self._open.get(key)
                if row is None:
                    self._open[key] = self._insert(connection, now, first_run)
                elif self._changed(row, connection) or now - row.written_at >= LAST_SEEN_REFRESH_SECONDS:
                    self._update(key, row, connection, now)
            for key in set(self._open) - set(current):
                row = self._open.pop(key)
                self._db.execute(CLOSE, (self._previous_time or now, now, row.id))
        self._previous_time = now
        self._prune_if_due()

    def close(self) -> None:
        if self._previous_time is not None:
            with self._db:
                for row in self._open.values():
                    self._db.execute("UPDATE connections SET last_seen = ? WHERE id = ?", (self._previous_time, row.id))
        self._open.clear()
        self._db.close()

    def _insert(self, connection: Connection, now: float, seen_at_start: bool) -> _OpenRow:
        process = connection.process
        cursor = self._db.execute(
            INSERT,
            (
                now,
                int(seen_at_start),
                now,
                connection.protocol.value,
                connection.local.ip,
                connection.local.port,
                connection.remote.ip,
                connection.remote.port,
                connection.status,
                connection.pid,
                connection.process_name,
                process.exe if process else None,
                int(process.exe_deleted) if process else 0,
                process.command if process else None,
                process.username if process else None,
                process.lineage if process else None,
                connection.bytes_sent,
                connection.bytes_received,
                *_name_columns(connection.remote_name),
            ),
        )
        return _OpenRow(
            cursor.lastrowid,
            connection.status,
            connection.bytes_sent,
            connection.bytes_received,
            connection.remote_name,
            now,
        )

    def _update(self, key: tuple, row: _OpenRow, connection: Connection, now: float) -> None:
        cursor = self._db.execute(
            UPDATE,
            (
                now,
                connection.status,
                connection.bytes_sent,
                connection.bytes_received,
                *_name_columns(connection.remote_name),
                row.id,
            ),
        )
        if cursor.rowcount == 0:
            self._open[key] = self._insert(connection, now, False)
            return
        row.status = connection.status
        row.bytes_sent = connection.bytes_sent
        row.bytes_received = connection.bytes_received
        row.remote_name = connection.remote_name
        row.written_at = now

    @staticmethod
    def _changed(row: _OpenRow, connection: Connection) -> bool:
        return (row.status, row.bytes_sent, row.bytes_received, row.remote_name) != (
            connection.status,
            connection.bytes_sent,
            connection.bytes_received,
            connection.remote_name,
        )

    def _prune_if_due(self) -> None:
        now = self._clock()
        if self._pruned_at is not None and now - self._pruned_at < PRUNE_INTERVAL_SECONDS:
            return
        self._pruned_at = now
        prune(self._db, self._retention_days, now)


def _name_columns(name: RemoteName | None) -> tuple[str | None, int | None]:
    if name is None:
        return None, None
    return name.name, int(name.confirmed)


def prune(db: sqlite3.Connection, retention_days: int, now: float) -> int:
    with db:
        cursor = db.execute("DELETE FROM connections WHERE last_seen < ?", (now - retention_days * SECONDS_PER_DAY,))
    return cursor.rowcount


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _where(query: HistoryQuery) -> tuple[str, list]:
    clauses = []
    params: list = []
    if query.since is not None:
        clauses.append("last_seen >= ?")
        params.append(query.since)
    if query.protocol is not None:
        clauses.append("protocol = ?")
        params.append(query.protocol.value)
    if query.search.strip():
        pattern = f"%{_escape_like(query.search.strip())}%"
        columns = ("process_label", "command", "exe", "remote_ip", "remote_name", "CAST(pid AS TEXT)")
        clauses.append("(" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in columns) + ")")
        params.extend([pattern] * len(columns))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


class HistoryReader:
    def __init__(self, path: Path) -> None:
        self._path = path

    def _connect(self) -> sqlite3.Connection:
        return open_database(self._path)

    def connections(self, query: HistoryQuery) -> list[HistoryEntry]:
        where, params = _where(query)
        db = self._connect()
        try:
            rows = db.execute(
                f"SELECT * FROM connections{where} ORDER BY first_seen DESC, id DESC LIMIT ?", [*params, query.limit]
            ).fetchall()
        finally:
            db.close()
        return [
            HistoryEntry(
                id=row["id"],
                first_seen=row["first_seen"],
                seen_at_start=bool(row["seen_at_start"]),
                last_seen=row["last_seen"],
                closed_at=row["closed_at"],
                protocol=Protocol(row["protocol"]),
                remote_ip=row["remote_ip"],
                remote_port=row["remote_port"],
                status=row["status"],
                pid=row["pid"],
                process_label=row["process_label"],
                exe=row["exe"],
                exe_deleted=bool(row["exe_deleted"]),
                command=row["command"],
                username=row["username"],
                lineage=row["lineage"],
                bytes_sent=row["bytes_sent"],
                bytes_received=row["bytes_received"],
                remote_name=row["remote_name"],
                remote_name_confirmed=bool(row["remote_name_confirmed"]),
            )
            for row in rows
        ]

    def processes(self, query: HistoryQuery) -> list[ProcessHistory]:
        where, params = _where(query)
        db = self._connect()
        try:
            rows = db.execute(
                f"""
                SELECT process_label, exe, MAX(command) AS command, COUNT(*) AS connection_count,
                       COUNT(DISTINCT remote_ip) AS destination_count,
                       SUM(bytes_sent) AS bytes_sent, SUM(bytes_received) AS bytes_received,
                       MIN(first_seen) AS first_seen,
                       MIN(CASE WHEN seen_at_start THEN first_seen END) = MIN(first_seen) AS first_seen_at_start,
                       MAX(last_seen) AS last_seen,
                       MAX(exe_deleted) AS exe_deleted
                FROM connections{where}
                GROUP BY process_label, exe
                ORDER BY COALESCE(SUM(bytes_sent), 0) DESC, connection_count DESC
                LIMIT ?
                """,
                [*params, query.limit],
            ).fetchall()
        finally:
            db.close()
        return [
            ProcessHistory(
                process_label=row["process_label"],
                exe=row["exe"],
                command=row["command"],
                connection_count=row["connection_count"],
                destination_count=row["destination_count"],
                bytes_sent=row["bytes_sent"],
                bytes_received=row["bytes_received"],
                first_seen=row["first_seen"],
                first_seen_at_start=bool(row["first_seen_at_start"]),
                last_seen=row["last_seen"],
                exe_deleted=bool(row["exe_deleted"]),
            )
            for row in rows
        ]

    def clear(self) -> None:
        db = self._connect()
        try:
            with db:
                db.execute("DELETE FROM connections")
            db.execute("VACUUM")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            db.close()
