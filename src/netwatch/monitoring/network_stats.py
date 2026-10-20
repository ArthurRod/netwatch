import time
from collections.abc import Callable, Mapping
from pathlib import Path

import psutil

from netwatch.models.connection import TrafficStats

CounterReader = Callable[[], Mapping[str, tuple[int, int]]]

SYS_CLASS_NET = Path("/sys/class/net")


def read_psutil_counters() -> dict[str, tuple[int, int]]:
    return {
        name: (counters.bytes_sent, counters.bytes_recv)
        for name, counters in psutil.net_io_counters(pernic=True).items()
    }


def is_physical_interface(name: str, sys_class_net: Path = SYS_CLASS_NET) -> bool:
    return (sys_class_net / name / "device").exists()


class NetworkStatsTracker:
    def __init__(
        self,
        read_counters: CounterReader = read_psutil_counters,
        is_physical: Callable[[str], bool] = is_physical_interface,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._read_counters = read_counters
        self._is_physical = is_physical
        self._clock = clock
        self._previous: dict[str, tuple[int, int]] = {}
        self._previous_time: float | None = None
        self._session_sent = 0
        self._session_received = 0

    def reset_baseline(self) -> None:
        self._previous = {}
        self._previous_time = None

    def sample(self) -> TrafficStats:
        now = self._clock()
        counters = self._select_interfaces(self._read_counters())

        sent_delta = 0
        received_delta = 0
        for name, (sent, received) in counters.items():
            previous = self._previous.get(name)
            if previous is None:
                continue
            sent_delta += max(sent - previous[0], 0)
            received_delta += max(received - previous[1], 0)

        elapsed = None if self._previous_time is None else now - self._previous_time
        self._previous = dict(counters)
        self._previous_time = now
        self._session_sent += sent_delta
        self._session_received += received_delta

        has_rate = elapsed is not None and elapsed > 0
        return TrafficStats(
            sent_per_second=sent_delta / elapsed if has_rate else None,
            received_per_second=received_delta / elapsed if has_rate else None,
            session_sent=self._session_sent,
            session_received=self._session_received,
            interfaces=tuple(sorted(counters)),
        )

    def _select_interfaces(
        self, counters: Mapping[str, tuple[int, int]]
    ) -> dict[str, tuple[int, int]]:
        physical = {name: value for name, value in counters.items() if self._is_physical(name)}
        if physical:
            return physical
        return {name: value for name, value in counters.items() if name != "lo"}
