import subprocess

from netwatch.monitoring.collector import SnapshotBuilder
from netwatch.monitoring.connections import ConnectionCollector
from netwatch.monitoring.network_stats import NetworkStatsTracker
from netwatch.monitoring.socket_stats import SocketStatsReader
from netwatch.services import monitor_service
from netwatch.services.domain_resolver import DomainResolver


class CountingBuilder:
    def __init__(self):
        self.resets = 0

    def reset_rates(self):
        self.resets += 1


def test_long_wall_clock_gap_resets_rates_after_suspend(monkeypatch, qapp):
    now = [1000.0]
    monkeypatch.setattr(monitor_service, "time", lambda: now[0])
    worker = monitor_service._Worker(1000, None, 30, False)
    builder = CountingBuilder()
    worker._builder = builder
    worker._reset_rates_after_suspend()
    now[0] += 1.0
    worker._reset_rates_after_suspend()
    assert builder.resets == 0
    now[0] += 3600
    worker._reset_rates_after_suspend()
    assert builder.resets == 1


def test_network_down_everything_unavailable_still_builds_snapshot():
    def no_counters():
        return {}

    def ss_fails():
        raise subprocess.CalledProcessError(1, "ss")

    def dns_fails(ip):
        raise OSError("network unreachable")

    builder = SnapshotBuilder(
        ConnectionCollector(lambda: [], read_local_addresses=set),
        NetworkStatsTracker(no_counters, lambda name: True),
        sockets=SocketStatsReader(ss_fails),
        resolver=DomainResolver(dns_fails, workers=1),
    )
    first = builder.build()
    second = builder.build()
    assert first.connections == ()
    assert second.traffic.sent_per_second == 0
    assert second.traffic.interfaces == ()
    assert second.outbound_by_process == ()
    builder.close()


def test_interface_going_down_and_up_does_not_spike():
    samples = iter([
        {"enp4s0": (1_000_000, 1_000_000)},
        {},
        {"enp4s0": (10, 10)},
        {"enp4s0": (110, 210)},
    ])
    clock = iter([0.0, 1.0, 2.0, 3.0])
    tracker = NetworkStatsTracker(lambda: next(samples), lambda name: True, lambda: next(clock))
    rates = [tracker.sample().sent_per_second for _ in range(4)]
    assert rates == [None, 0, 0, 100]
