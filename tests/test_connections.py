import socket
from collections import namedtuple
from datetime import datetime, timedelta

import psutil

from netwatch.models.connection import Connection, Endpoint, Protocol, is_external_ip
from netwatch.monitoring.collector import SnapshotBuilder, summarize_outbound
from netwatch.models.process import ProcessIdentity
from netwatch.monitoring.connections import ConnectionCollector, ProcessCache, normalize_connection
from netwatch.models.connection import TrafficStats

Addr = namedtuple("Addr", "ip port")
RawConn = namedtuple("RawConn", "fd family type laddr raddr status pid")


def identity(name, pid=10):
    return ProcessIdentity(pid, name, f"/usr/bin/{name}", False, (name,), "user", ())


def raw(remote=None, pid=10, kind=socket.SOCK_STREAM, status="ESTABLISHED", local=("192.168.0.2", 50000)):
    return RawConn(-1, socket.AF_INET, kind, Addr(*local), Addr(*remote) if remote else (), status, pid)


def conn(name, ip, port=443, pid=1):
    return Connection(Protocol.TCP, Endpoint("192.168.0.2", 50000 + port), Endpoint(ip, port), "ESTABLISHED", pid, name)


def test_normalize_tcp_with_remote():
    connection = normalize_connection(raw(("142.250.1.1", 443)), identity("firefox"))
    assert connection.protocol is Protocol.TCP
    assert connection.remote == Endpoint("142.250.1.1", 443)
    assert connection.process_name == "firefox"
    assert connection.is_outbound


def test_normalize_udp_without_remote_and_none_status():
    connection = normalize_connection(raw(None, kind=socket.SOCK_DGRAM, status=psutil.CONN_NONE), None)
    assert connection.protocol is Protocol.UDP
    assert connection.remote is None
    assert connection.status is None
    assert not connection.is_outbound


def test_is_external_ip():
    assert is_external_ip("8.8.8.8")
    assert is_external_ip("192.168.0.10")
    assert not is_external_ip("127.0.0.1")
    assert not is_external_ip("::1")
    assert not is_external_ip("::ffff:127.0.0.1")
    assert not is_external_ip("0.0.0.0")
    assert is_external_ip("fe80::1%enp4s0")
    assert not is_external_ip("not-an-ip")


def test_process_cache_looks_up_once_and_prunes():
    calls = []

    def lookup(pid):
        calls.append(pid)
        return identity(f"proc{pid}", pid)

    cache = ProcessCache(lookup)
    assert cache.get(1).name == "proc1"
    assert cache.get(1).name == "proc1"
    assert cache.get(None) is None
    cache.retain(set())
    cache.get(1)
    assert calls == [1, 1]


def test_collector_handles_access_denied():
    def denied():
        raise psutil.AccessDenied()

    assert ConnectionCollector(denied, ProcessCache(lambda pid: None)).collect() == []


def test_summarize_outbound_groups_by_process_and_puts_unknown_last():
    summary = summarize_outbound(
        [
            conn("firefox", "1.1.1.1"),
            conn("firefox", "2.2.2.2", 80),
            conn("firefox", "1.1.1.1", 8443),
            conn(None, "9.9.9.9"),
            conn("cursor", "3.3.3.3"),
            Connection(Protocol.TCP, Endpoint("127.0.0.1", 1), Endpoint("127.0.0.1", 2), "ESTABLISHED", 5, "local"),
        ]
    )
    assert [s.process_name for s in summary] == ["firefox", "cursor", None]
    assert summary[0].connection_count == 3
    assert summary[0].destinations == ("1.1.1.1", "2.2.2.2")


class StaticStats:
    def sample(self):
        return TrafficStats(None, None, 0, 0, ("enp4s0",))

    def reset_baseline(self):
        pass


class NoSockets:
    def read(self):
        return None


def test_snapshot_builder_tracks_first_seen_and_recent():
    batches = [
        [raw(("1.1.1.1", 443), pid=1)],
        [raw(("1.1.1.1", 443), pid=1), raw(("2.2.2.2", 443), pid=2, local=("192.168.0.2", 50001))],
        [raw(("2.2.2.2", 443), pid=2, local=("192.168.0.2", 50001)), raw(None, pid=None)],
    ]
    times = iter([datetime(2026, 1, 1) + timedelta(seconds=i) for i in range(3)])
    builder = SnapshotBuilder(
        ConnectionCollector(lambda: batches.pop(0), ProcessCache(lambda pid: identity(f"p{pid}", pid))),
        StaticStats(),
        lambda: next(times),
        NoSockets(),
    )

    first = builder.build()
    assert [c.process_name for c in first.recent_outbound] == ["p1"]

    second = builder.build()
    assert [c.process_name for c in second.recent_outbound] == ["p2", "p1"]
    assert second.connections[0].first_seen == datetime(2026, 1, 1)

    third = builder.build()
    assert third.outbound_count == 1
    assert third.connections[0].first_seen == datetime(2026, 1, 1, 0, 0, 1)
    assert third.unattributed_outbound == 0


def test_time_wait_is_not_counted_as_outbound():
    closed = normalize_connection(raw(("1.1.1.1", 443), pid=None, status="TIME_WAIT"), None)
    assert closed.is_closed
    assert not closed.is_outbound
