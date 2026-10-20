from datetime import datetime

from netwatch.models.connection import Connection, Endpoint, Protocol, TrafficStats
from netwatch.monitoring.collector import SnapshotBuilder, attach_socket_bytes, summarize_outbound
from netwatch.monitoring.process_traffic import ProcessTrafficTracker
from netwatch.monitoring.socket_stats import SocketBytes, SocketStatsReader, parse_ss

SS_OUTPUT = """ESTAB 0      0                                192.168.100.89:55080                 34.107.243.93:443
\t cubic wscale:8,10 rto:216 bytes_sent:3336 bytes_acked:3337 bytes_received:1162 segs_out:9
ESTAB 0      0      [2804:d45::f42a]:47746          [2600:1901:0:9e23::]:443
\t cubic rto:204 bytes_sent:10 bytes_acked:11 bytes_received:20
SYN-SENT 0   1                                192.168.100.89:40000                 1.2.3.4:443
\t cubic rto:1000
"""


def tcp(name, local_port, ip="9.9.9.9", sent=None, pid=1):
    return Connection(
        Protocol.TCP, Endpoint("192.168.0.2", local_port), Endpoint(ip, 443), "ESTABLISHED", pid, name, bytes_sent=sent
    )


class Clock:
    def __init__(self, *values):
        self._values = list(values)

    def __call__(self):
        return self._values.pop(0)


def test_parse_ss_ipv4_ipv6_and_missing_fields():
    sockets = parse_ss(SS_OUTPUT)
    assert sockets[(Endpoint("192.168.100.89", 55080), Endpoint("34.107.243.93", 443))] == SocketBytes(3337, 1162)
    assert sockets[(Endpoint("2804:d45::f42a", 47746), Endpoint("2600:1901:0:9e23::", 443))] == SocketBytes(11, 20)
    assert sockets[(Endpoint("192.168.100.89", 40000), Endpoint("1.2.3.4", 443))] == SocketBytes(0, 0)


def test_reader_returns_none_when_ss_fails():
    def failing():
        raise FileNotFoundError("ss")

    assert SocketStatsReader(failing).read() is None


def test_attach_matches_tcp_by_local_and_remote():
    connection = tcp("firefox", 50000)
    udp = Connection(Protocol.UDP, connection.local, connection.remote, None, 1, "firefox")
    sockets = {(connection.local, connection.remote): SocketBytes(100, 50)}
    attached = attach_socket_bytes([connection, udp], sockets)
    assert (attached[0].bytes_sent, attached[0].bytes_received) == (100, 50)
    assert attached[1].bytes_sent is None


def test_first_update_is_baseline_then_deltas_become_rates():
    tracker = ProcessTrafficTracker(Clock(0.0, 2.0))
    first = tracker.update([tcp("firefox", 1, sent=1000)])
    assert first.sent_per_second is None
    assert first.session_sent == {}

    second = tracker.update([tcp("firefox", 1, sent=3000), tcp("curl", 2, sent=400)])
    assert second.sent_per_second == {"firefox": 1000.0, "curl": 200.0}
    assert second.session_sent == {"firefox": 2000, "curl": 400}


def test_session_total_survives_process_closing_its_connections():
    tracker = ProcessTrafficTracker(Clock(0.0, 1.0, 2.0))
    tracker.update([])
    tracker.update([tcp("script", 1, ip="6.6.6.6", sent=5000)])
    report = tracker.update([])
    assert report.session_sent == {"script": 5000}
    assert report.destinations["script"] == ("6.6.6.6",)

    summary = summarize_outbound([], report)
    assert summary[0].process_name == "script"
    assert summary[0].connection_count == 0
    assert summary[0].session_sent == 5000
    assert summary[0].sent_per_second == 0.0


def test_shared_socket_is_counted_once():
    tracker = ProcessTrafficTracker(Clock(0.0, 1.0))
    tracker.update([tcp("a", 1, sent=0)])
    report = tracker.update([tcp("a", 1, sent=100), tcp("b", 1, sent=100, pid=2)])
    assert report.session_sent == {"a": 100}


def test_counter_going_backwards_is_ignored():
    tracker = ProcessTrafficTracker(Clock(0.0, 1.0))
    tracker.update([tcp("a", 1, sent=500)])
    assert tracker.update([tcp("a", 1, sent=100)]).session_sent == {}


def test_summary_ranks_by_bytes_sent_not_connection_count():
    tracker = ProcessTrafficTracker(Clock(0.0, 1.0))
    many = [tcp("browser", port, sent=0) for port in range(1, 6)]
    tracker.update([*many, tcp("exfil", 99, sent=0)])
    report = tracker.update([*many, tcp("exfil", 99, sent=10_000_000)])
    summary = summarize_outbound([*many, tcp("exfil", 99, sent=10_000_000)], report)
    assert [s.process_name for s in summary] == ["exfil", "browser"]


class FixedStats:
    def __init__(self, rate):
        self._rate = rate

    def sample(self):
        return TrafficStats(self._rate, 0.0, 0, 0, ("enp4s0",))

    def reset_baseline(self):
        pass


class FakeCollector:
    def __init__(self, *batches):
        self._batches = list(batches)

    def collect(self):
        return self._batches.pop(0)


class FakeSockets:
    def __init__(self, *batches):
        self._batches = list(batches)

    def read(self):
        return self._batches.pop(0)


def test_builder_reports_unattributed_rate():
    connection = tcp("app", 1)
    key = (connection.local, connection.remote)
    builder = SnapshotBuilder(
        FakeCollector([connection], [connection]),
        FixedStats(1000.0),
        lambda: datetime(2026, 1, 1),
        FakeSockets({key: SocketBytes(0, 0)}, {key: SocketBytes(700, 0)}),
        ProcessTrafficTracker(Clock(0.0, 1.0)),
    )
    assert builder.build().unattributed_sent_per_second is None
    snapshot = builder.build()
    assert snapshot.unattributed_sent_per_second == 300.0
    assert snapshot.connections[0].bytes_sent == 700
