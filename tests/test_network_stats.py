from pathlib import Path

from netwatch.monitoring.network_stats import NetworkStatsTracker, is_physical_interface


class FakeCounters:
    def __init__(self, *samples):
        self._samples = list(samples)

    def __call__(self):
        return self._samples.pop(0)


class FakeClock:
    def __init__(self, *times):
        self._times = list(times)

    def __call__(self):
        return self._times.pop(0)


def physical(name):
    return name.startswith("enp")


def test_first_sample_has_unknown_rates():
    tracker = NetworkStatsTracker(FakeCounters({"enp4s0": (100, 200)}), physical, FakeClock(0.0))
    stats = tracker.sample()
    assert stats.sent_per_second is None
    assert stats.received_per_second is None
    assert stats.session_sent == 0


def test_rates_and_session_totals():
    tracker = NetworkStatsTracker(
        FakeCounters({"enp4s0": (100, 200)}, {"enp4s0": (1100, 4200)}, {"enp4s0": (2100, 4200)}),
        physical,
        FakeClock(0.0, 2.0, 3.0),
    )
    tracker.sample()
    second = tracker.sample()
    assert second.sent_per_second == 500
    assert second.received_per_second == 2000
    third = tracker.sample()
    assert third.sent_per_second == 1000
    assert third.session_sent == 2000
    assert third.session_received == 4000


def test_virtual_interfaces_are_ignored_when_physical_exists():
    tracker = NetworkStatsTracker(
        FakeCounters(
            {"enp4s0": (0, 0), "docker0": (0, 0), "veth1": (0, 0), "lo": (0, 0)},
            {"enp4s0": (10, 0), "docker0": (500, 0), "veth1": (500, 0), "lo": (900, 0)},
        ),
        physical,
        FakeClock(0.0, 1.0),
    )
    tracker.sample()
    stats = tracker.sample()
    assert stats.sent_per_second == 10
    assert stats.interfaces == ("enp4s0",)


def test_falls_back_to_non_loopback_without_physical_interfaces():
    tracker = NetworkStatsTracker(
        FakeCounters({"wg0": (0, 0), "lo": (0, 0)}, {"wg0": (30, 0), "lo": (900, 0)}),
        lambda name: False,
        FakeClock(0.0, 1.0),
    )
    tracker.sample()
    assert tracker.sample().sent_per_second == 30


def test_counter_reset_and_new_interface_do_not_produce_negative_or_spurious_traffic():
    tracker = NetworkStatsTracker(
        FakeCounters({"enp4s0": (5000, 5000)}, {"enp4s0": (100, 100), "enp5s0": (999, 999)}),
        physical,
        FakeClock(0.0, 1.0),
    )
    tracker.sample()
    stats = tracker.sample()
    assert stats.sent_per_second == 0
    assert stats.session_sent == 0


def test_reset_baseline_makes_next_rate_unknown():
    tracker = NetworkStatsTracker(
        FakeCounters({"enp4s0": (0, 0)}, {"enp4s0": (10, 0)}),
        physical,
        FakeClock(0.0, 100.0),
    )
    tracker.sample()
    tracker.reset_baseline()
    assert tracker.sample().sent_per_second is None


def test_is_physical_interface(tmp_path: Path):
    (tmp_path / "enp4s0" / "device").mkdir(parents=True)
    (tmp_path / "docker0").mkdir()
    assert is_physical_interface("enp4s0", tmp_path)
    assert not is_physical_interface("docker0", tmp_path)
