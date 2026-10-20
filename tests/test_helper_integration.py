import os
import time
from datetime import datetime, timedelta

import netwatch_helper as helper

from netwatch.models.connection import Connection, Endpoint, Protocol, TrafficStats
from netwatch.models.domain import NameSource
from netwatch.models.history import HistoryQuery
from netwatch.monitoring.collector import SnapshotBuilder
from netwatch.monitoring.helper_events import HelperState
from netwatch.monitoring.process_traffic import ProcessTrafficTracker
from netwatch.monitoring.socket_stats import SocketBytes
from netwatch.services.helper_client import HelperClient
from netwatch.storage.history import HistoryReader, HistoryRecorder

ROOT_PROCESS = {
    "pid": 777,
    "name": "sync",
    "exe": "/tmp/.x/sync",
    "exe_deleted": True,
    "cmdline": ["/tmp/.x/sync", "--token", "s3cret"],
    "uid": 0,
    "cwd": "/",
    "ancestors": [[1, "systemd"]],
}


class FixedStats:
    def sample(self):
        return TrafficStats(10_000.0, 0.0, 0, 0, ("enp4s0",))

    def reset_baseline(self):
        pass


class Batches:
    def __init__(self, *batches):
        self._batches = list(batches)

    def collect(self):
        return self._batches.pop(0)

    def read(self):
        return self._batches.pop(0)


def wait_until(condition, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_helper_events_flow_into_snapshot_and_history(tmp_path):
    broadcaster = helper.Broadcaster()
    path = tmp_path / "events.sock"
    server = helper.EventServer(path, {os.getuid()}, broadcaster, {"type": "hello", "version": 1})
    server.start()
    client = HelperClient(path)
    client.start()
    assert wait_until(lambda: client.connected)
    assert wait_until(lambda: bool(broadcaster._clients))

    long_lived = Connection(Protocol.TCP, Endpoint("192.168.0.2", 40000), Endpoint("9.9.9.9", 443), "ESTABLISHED", None, None)
    key = (long_lived.local, long_lived.remote)
    clock = iter([0.0, 1.0, 2.0])
    times = iter([datetime(2026, 1, 1) + timedelta(seconds=i) for i in range(3)])
    builder = SnapshotBuilder(
        Batches([long_lived], [long_lived], []),
        FixedStats(),
        lambda: next(times),
        Batches({key: SocketBytes(1000, 0)}, {key: SocketBytes(4000, 0)}, {}),
        ProcessTrafficTracker(lambda: next(clock)),
        helper=HelperState(client),
    )

    broadcaster.publish({"type": "status", "tcp": "running", "dns": "running"})
    broadcaster.publish({"type": "dns", "questions": ["exfil.example"], "answers": {"exfil.example": ["6.6.6.6"]}})
    broadcaster.publish({"type": "tcp_connect", "sock": 1, "pid": 777, "uid": 0, "local": ["192.168.0.2", 40000], "remote": ["9.9.9.9", 443], "process": ROOT_PROCESS, "comm": "sync"})
    assert wait_until(lambda: client.status().get("tcp") == "running")
    time.sleep(0.2)
    first = builder.build()
    assert first.helper_active
    attributed = first.connections[0]
    assert attributed.pid == 777
    assert attributed.process.cmdline == ("/tmp/.x/sync", "--token", "***")

    broadcaster.publish({"type": "tcp_connect", "sock": 2, "pid": 777, "uid": 0, "local": ["192.168.0.2", 40001], "remote": ["6.6.6.6", 443], "process": ROOT_PROCESS, "comm": "sync"})
    broadcaster.publish({"type": "tcp_close", "sock": 2, "pid": 777, "uid": 0, "local": ["192.168.0.2", 40001], "remote": ["6.6.6.6", 443], "bytes_sent": 50_000, "bytes_received": 100, "process": ROOT_PROCESS, "comm": "sync"})
    time.sleep(0.2)
    second = builder.build()
    sync = next(s for s in second.outbound_by_process if s.process_name == "sync")
    assert sync.session_sent == 3000 + 50_000
    assert second.remote_names["6.6.6.6"].source is NameSource.DNS_OBSERVED
    assert any(c.remote.ip == "6.6.6.6" for c in second.recent_outbound)

    broadcaster.publish({"type": "tcp_close", "sock": 1, "pid": 777, "uid": 0, "local": ["192.168.0.2", 40000], "remote": ["9.9.9.9", 443], "bytes_sent": 4500, "bytes_received": 0, "process": ROOT_PROCESS, "comm": "sync"})
    time.sleep(0.2)
    third = builder.build()
    sync = next(s for s in third.outbound_by_process if s.process_name == "sync")
    assert sync.session_sent == (4500 - 1000) + 50_000

    recorder = HistoryRecorder(tmp_path / "history.db", 30, clock=lambda: 0.0)
    for snapshot in (first, second, third):
        recorder.record(snapshot)
    recorder.close()
    rows = {e.remote_ip: e for e in HistoryReader(tmp_path / "history.db").connections(HistoryQuery())}
    assert rows["6.6.6.6"].bytes_sent == 50_000 and rows["6.6.6.6"].closed_at is not None
    assert rows["6.6.6.6"].remote_name == "exfil.example"
    assert rows["6.6.6.6"].remote_name_source == "dns_observed"
    assert rows["9.9.9.9"].bytes_sent == 4500 and rows["9.9.9.9"].closed_at is not None
    assert rows["9.9.9.9"].exe_deleted

    client.close()
    server.stop()


def test_dns_ambiguity_is_reported():
    from netwatch.monitoring.helper_events import DnsNameTable

    table = DnsNameTable(clock=lambda: 100.0)
    table.ingest({"questions": ["a.example"], "answers": {"cdn.net": ["1.2.3.4"]}})
    table.ingest({"questions": ["b.example"], "answers": {"cdn.net": ["1.2.3.4"]}})
    name = table.name_for("1.2.3.4")
    assert name.source is NameSource.DNS_AMBIGUOUS
    assert {name.name, *name.alternatives} == {"a.example", "b.example"}
    assert not name.confirmed


def test_client_without_helper_stays_quiet(tmp_path):
    client = HelperClient(tmp_path / "missing.sock")
    client.start()
    time.sleep(0.2)
    assert not client.connected
    assert HelperState(client).status() == {}
    client.close()
