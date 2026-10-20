import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from netwatch.models.connection import Connection
from netwatch.models.process import ProcessIdentity
from netwatch.monitoring.socket_stats import SocketBytes, SocketKey

DESTINATIONS_PER_PROCESS = 20

GroupKey = str | None


@dataclass(frozen=True, slots=True)
class ProcessTrafficReport:
    sent_per_second: dict[GroupKey, float] | None
    session_sent: dict[GroupKey, int]
    session_received: dict[GroupKey, int]
    destinations: dict[GroupKey, tuple[str, ...]]
    processes: dict[GroupKey, ProcessIdentity]
    labels: dict[GroupKey, str | None]

    @property
    def attributed_sent_per_second(self) -> float | None:
        if self.sent_per_second is None:
            return None
        return sum(self.sent_per_second.values())


class ProcessTrafficTracker:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._previous: dict[SocketKey, SocketBytes] | None = None
        self._previous_time: float | None = None
        self._session_sent: dict[GroupKey, int] = {}
        self._session_received: dict[GroupKey, int] = {}
        self._destinations: dict[GroupKey, dict[str, None]] = {}
        self._processes: dict[GroupKey, ProcessIdentity] = {}
        self._labels: dict[GroupKey, str | None] = {}

    def reset_baseline(self) -> None:
        self._previous = None
        self._previous_time = None

    def update(self, connections: Iterable[Connection]) -> ProcessTrafficReport:
        now = self._clock()
        current: dict[SocketKey, SocketBytes] = {}
        sent_delta: dict[GroupKey, int] = {}
        received_delta: dict[GroupKey, int] = {}

        for connection in connections:
            if not connection.is_outbound or connection.bytes_sent is None:
                continue
            key = (connection.local, connection.remote)
            if key in current:
                continue
            counters = SocketBytes(connection.bytes_sent, connection.bytes_received or 0)
            current[key] = counters
            self._remember(connection)
            if self._previous is None:
                continue
            previous = self._previous.get(key)
            group = connection.group_key
            delta = counters.sent - previous.sent if previous else counters.sent
            if delta > 0:
                sent_delta[group] = sent_delta.get(group, 0) + delta
            received = counters.received - previous.received if previous else counters.received
            if received > 0:
                received_delta[group] = received_delta.get(group, 0) + received

        for name, delta in sent_delta.items():
            self._session_sent[name] = self._session_sent.get(name, 0) + delta
        for name, delta in received_delta.items():
            self._session_received[name] = self._session_received.get(name, 0) + delta

        elapsed = None if self._previous_time is None else now - self._previous_time
        self._previous = current
        self._previous_time = now

        rates = None
        if elapsed is not None and elapsed > 0:
            rates = {name: delta / elapsed for name, delta in sent_delta.items()}
        return ProcessTrafficReport(
            sent_per_second=rates,
            session_sent=dict(self._session_sent),
            session_received=dict(self._session_received),
            destinations={name: tuple(reversed(ips)) for name, ips in self._destinations.items()},
            processes=dict(self._processes),
            labels=dict(self._labels),
        )

    def _remember(self, connection: Connection) -> None:
        group = connection.group_key
        self._labels[group] = connection.process_name
        if connection.process is not None:
            self._processes[group] = connection.process
        known = self._destinations.setdefault(group, {})
        ip = connection.remote.ip
        if ip in known:
            known.pop(ip)
        elif len(known) >= DESTINATIONS_PER_PROCESS:
            known.pop(next(iter(known)))
        known[ip] = None
