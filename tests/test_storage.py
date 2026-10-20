import csv
import sqlite3
import stat
from datetime import datetime

from netwatch.models.connection import Connection, Endpoint, Protocol, Snapshot, TrafficStats
from netwatch.models.history import HistoryQuery
from netwatch.models.process import ProcessIdentity
from netwatch.services.export_service import export_connections, safe_cell
from netwatch.storage.history import SECONDS_PER_DAY, HistoryReader, HistoryRecorder

BASE = datetime(2026, 10, 20, 12, 0, 0).timestamp()


def process(name="python3", script="/tmp/.x/sync.py", pid=42):
    return ProcessIdentity(pid, name, "/usr/bin/python3", False, (name, script), "user", ((1, "systemd"),))


def tcp(port, sent=None, status="ESTABLISHED", proc=None, ip="6.6.6.6"):
    proc = proc or process()
    return Connection(
        Protocol.TCP,
        Endpoint("192.168.0.2", port),
        Endpoint(ip, 443),
        status,
        proc.pid,
        proc.label,
        bytes_sent=sent,
        process=proc,
    )


def snapshot(offset, *connections):
    return Snapshot(
        taken_at=datetime.fromtimestamp(BASE + offset),
        traffic=TrafficStats(None, None, 0, 0, ()),
        connections=tuple(connections),
        outbound_by_process=(),
        recent_outbound=(),
        unattributed_outbound=0,
    )


def recorder(path, now=BASE):
    return HistoryRecorder(path, retention_days=30, clock=lambda: now)


def test_lifecycle_insert_update_close(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 0)))
    rec.record(snapshot(1, tcp(1, 500), tcp(2, 10)))
    rec.record(snapshot(2, tcp(2, 10)))
    rec.close()

    entries = {e.bytes_sent: e for e in HistoryReader(path).connections(HistoryQuery())}
    first, second = entries[500], entries[10]
    assert first.seen_at_start is True
    assert first.closed_at == BASE + 2
    assert first.last_seen == BASE + 1
    assert first.command == "python3 /tmp/.x/sync.py"
    assert first.lineage == "systemd (1)"
    assert second.seen_at_start is False
    assert second.first_seen == BASE + 1
    assert second.closed_at is None
    assert second.last_seen == BASE + 2


def test_unchanged_rows_are_not_rewritten_every_tick(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 100)))
    rec.record(snapshot(5, tcp(1, 100)))
    rec._db.commit()
    assert HistoryReader(path).connections(HistoryQuery())[0].last_seen == BASE
    rec.record(snapshot(61, tcp(1, 100)))
    assert HistoryReader(path).connections(HistoryQuery())[0].last_seen == BASE + 61
    rec.close()


def test_time_wait_closes_the_row(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 100)))
    rec.record(snapshot(1, tcp(1, 100, status="TIME_WAIT")))
    rec.close()
    assert HistoryReader(path).connections(HistoryQuery())[0].closed_at == BASE + 1


def test_recorder_reinserts_after_history_is_cleared(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 100)))
    HistoryReader(path).clear()
    rec.record(snapshot(1, tcp(1, 200)))
    rec.close()
    entries = HistoryReader(path).connections(HistoryQuery())
    assert [e.bytes_sent for e in entries] == [200]


def test_retention_prunes_old_rows(tmp_path):
    path = tmp_path / "history.db"
    old = recorder(path)
    old.record(snapshot(0, tcp(1, 1)))
    old.close()
    later = recorder(path, now=BASE + 31 * SECONDS_PER_DAY)
    later.record(snapshot(31 * SECONDS_PER_DAY, tcp(2, 2)))
    later.close()
    assert [e.bytes_sent for e in HistoryReader(path).connections(HistoryQuery())] == [2]


def test_query_filters_and_like_escaping(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    browser = process("firefox", "", pid=7)
    rec.record(snapshot(0, tcp(1, 5, proc=browser, ip="1.1.1.1"), tcp(2, 9)))
    rec.close()
    reader = HistoryReader(path)
    assert [e.process_label for e in reader.connections(HistoryQuery(search="/tmp/.x"))] == ["python3 sync.py"]
    assert [e.remote_ip for e in reader.connections(HistoryQuery(search="1.1.1"))] == ["1.1.1.1"]
    assert reader.connections(HistoryQuery(search="%")) == []
    assert reader.connections(HistoryQuery(protocol=Protocol.UDP)) == []
    assert reader.connections(HistoryQuery(since=BASE + 10)) == []


def test_process_view_sums_and_ranks_by_bytes_sent(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    browser = process("firefox", "", pid=7)
    rec.record(
        snapshot(
            0,
            tcp(1, 100, proc=browser, ip="1.1.1.1"),
            tcp(2, 200, proc=browser, ip="2.2.2.2"),
            tcp(3, 5000, ip="6.6.6.6"),
            tcp(4, 5000, ip="6.6.6.6"),
        )
    )
    rec.close()
    processes = HistoryReader(path).processes(HistoryQuery())
    assert [(p.process_label, p.bytes_sent, p.connection_count, p.destination_count) for p in processes] == [
        ("python3 sync.py", 10000, 2, 1),
        ("firefox", 300, 2, 2),
    ]


def test_database_files_are_private(tmp_path):
    path = tmp_path / "netwatch" / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 1)))
    rec.close()
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    for candidate in path.parent.iterdir():
        assert stat.S_IMODE(candidate.stat().st_mode) == 0o600, candidate.name


def test_clear_removes_data_from_file(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 1, proc=process("python3", "/tmp/very-unique-marker.py"))))
    rec.close()
    HistoryReader(path).clear()
    assert b"very-unique-marker" not in path.read_bytes()


def test_csv_neutralizes_formulas(tmp_path):
    assert safe_cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    assert safe_cell("-c") == "'-c"
    assert safe_cell("firefox") == "firefox"
    assert safe_cell(None) == ""

    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 1, proc=process("python3", "=cmd|' /C calc'!A0"))))
    rec.close()
    out = tmp_path / "out.csv"
    export_connections(HistoryReader(path).connections(HistoryQuery()), out)
    rows = list(csv.reader(out.open(encoding="utf-8")))
    command = rows[1][rows[0].index("comando")]
    assert command.startswith("python3 =cmd")
    label = rows[1][rows[0].index("processo")]
    assert not label.startswith("=")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_schema_version_is_set(tmp_path):
    path = tmp_path / "history.db"
    recorder(path).close()
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0] == 3


def test_migrates_v1_database_and_keeps_rows(tmp_path):
    from netwatch.storage.database import SCHEMA_V1, open_database

    path = tmp_path / "history.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(SCHEMA_V1 + "PRAGMA user_version=1;")
    legacy.execute(
        "INSERT INTO connections (first_seen, seen_at_start, last_seen, protocol, local_ip, local_port, "
        "remote_ip, remote_port) VALUES (1, 0, 1, 'TCP', 'a', 1, '6.6.6.6', 443)"
    )
    legacy.commit()
    legacy.close()
    db = open_database(path)
    row = db.execute("SELECT remote_ip, remote_name FROM connections").fetchone()
    assert (row["remote_ip"], row["remote_name"]) == ("6.6.6.6", None)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 3


def test_concurrent_opens_migrate_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from netwatch.storage.database import open_database

    path = tmp_path / "history.db"

    def open_and_read_columns(_):
        db = open_database(path)
        try:
            return [row[1] for row in db.execute("PRAGMA table_info(connections)")]
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(open_and_read_columns, range(8)))
    assert all(columns.count("remote_name") == 1 for columns in results)


def test_process_first_seen_flags_connections_open_before_monitoring(tmp_path):
    path = tmp_path / "history.db"
    first_run = recorder(path)
    first_run.record(snapshot(0, tcp(1, 1)))
    first_run.close()
    second_run = recorder(path)
    second_run.record(snapshot(100, tcp(2, 1, proc=process("curl", "", pid=9))))
    second_run.record(snapshot(101, tcp(2, 1, proc=process("curl", "", pid=9)), tcp(3, 1)))
    second_run.close()
    by_label = {p.process_label: p for p in HistoryReader(path).processes(HistoryQuery())}
    assert by_label["python3 sync.py"].first_seen == BASE
    assert by_label["python3 sync.py"].first_seen_at_start is True
    assert by_label["curl"].first_seen_at_start is True


def test_byte_updates_are_throttled_but_close_writes_latest(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 100)))
    for second in range(1, 10):
        rec.record(snapshot(second, tcp(1, 100 + second * 10)))
    rec._db.commit()
    assert HistoryReader(path).connections(HistoryQuery())[0].bytes_sent == 100
    rec.record(snapshot(16, tcp(1, 900)))
    assert HistoryReader(path).connections(HistoryQuery())[0].bytes_sent == 900
    rec.record(snapshot(17, tcp(1, 950)))
    rec.record(snapshot(18))
    rec.close()
    entry = HistoryReader(path).connections(HistoryQuery())[0]
    assert entry.bytes_sent == 950
    assert entry.closed_at == BASE + 18


def test_app_close_writes_latest_bytes_of_open_rows(tmp_path):
    path = tmp_path / "history.db"
    rec = recorder(path)
    rec.record(snapshot(0, tcp(1, 100)))
    rec.record(snapshot(1, tcp(1, 300)))
    rec.close()
    entry = HistoryReader(path).connections(HistoryQuery())[0]
    assert (entry.bytes_sent, entry.closed_at, entry.last_seen) == (300, None, BASE + 1)
