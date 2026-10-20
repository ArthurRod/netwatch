import os
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 3
BUSY_TIMEOUT_MS = 5000
WAL_RETRY_SECONDS = 0.05
JOURNAL_SIZE_LIMIT_BYTES = 1024 * 1024

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY,
    first_seen REAL NOT NULL,
    seen_at_start INTEGER NOT NULL,
    last_seen REAL NOT NULL,
    closed_at REAL,
    protocol TEXT NOT NULL,
    local_ip TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    status TEXT,
    pid INTEGER,
    process_label TEXT,
    exe TEXT,
    exe_deleted INTEGER NOT NULL DEFAULT 0,
    command TEXT,
    username TEXT,
    lineage TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER
);
CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connections(last_seen);
CREATE INDEX IF NOT EXISTS idx_connections_first_seen ON connections(first_seen);
"""

MIGRATIONS = {
    1: SCHEMA_V1,
    2: """
ALTER TABLE connections ADD COLUMN remote_name TEXT;
ALTER TABLE connections ADD COLUMN remote_name_confirmed INTEGER;
""",
    3: """
ALTER TABLE connections ADD COLUMN remote_name_source TEXT;
""",
}


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "netwatch"


def default_database_path() -> Path:
    return data_dir() / "history.db"


def _secure_file(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = path.with_name(path.name + suffix)
        if candidate.exists():
            candidate.chmod(0o600)


def open_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if not path.exists():
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
    connection = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000)
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    connection.execute(f"PRAGMA journal_size_limit={JOURNAL_SIZE_LIMIT_BYTES}")
    _enable_wal(connection)
    _migrate(connection)
    _secure_file(path)
    return connection


def _enable_wal(connection: sqlite3.Connection) -> None:
    deadline = time.monotonic() + BUSY_TIMEOUT_MS / 1000
    while True:
        try:
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
                connection.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as error:
            if "locked" not in str(error) or time.monotonic() > deadline:
                raise
            time.sleep(WAL_RETRY_SECONDS)


def _migrate(connection: sqlite3.Connection) -> None:
    while True:
        connection.execute("BEGIN IMMEDIATE")
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version >= SCHEMA_VERSION:
                connection.execute("COMMIT")
                return
            target = version + 1
            for statement in MIGRATIONS[target].split(";"):
                if statement.strip():
                    connection.execute(statement)
            connection.execute(f"PRAGMA user_version={target}")
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
