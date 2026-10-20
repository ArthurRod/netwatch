from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import datetime

from netwatch.models.connection import Connection, ProcessOutbound, Protocol, Snapshot
from netwatch.models.domain import RemoteName
from netwatch.monitoring.connections import ConnectionCollector
from netwatch.monitoring.network_stats import NetworkStatsTracker
from netwatch.monitoring.process_traffic import ProcessTrafficReport, ProcessTrafficTracker
from netwatch.monitoring.socket_stats import SocketBytes, SocketKey, SocketStatsReader
from netwatch.services.domain_resolver import DomainResolver

RECENT_LIMIT = 50


def summarize_outbound(
    connections: Iterable[Connection], report: ProcessTrafficReport | None = None
) -> tuple[ProcessOutbound, ...]:
    groups: dict[str | None, list[Connection]] = {}
    for connection in connections:
        if connection.is_outbound:
            groups.setdefault(connection.group_key, []).append(connection)

    keys = set(groups)
    if report is not None:
        keys |= {key for key, sent in report.session_sent.items() if sent > 0}

    summaries = []
    for key in keys:
        items = groups.get(key, [])
        history = report.destinations.get(key, ()) if report else ()
        current = [c.remote.ip for c in items if c.remote]
        process = items[0].process if items else None
        label = items[0].process_name if items else None
        if report is not None:
            process = process or report.processes.get(key)
            label = label or report.labels.get(key)
        rate = None
        if report is not None and report.sent_per_second is not None:
            rate = report.sent_per_second.get(key, 0.0)
        summaries.append(
            ProcessOutbound(
                process_name=label,
                process=process,
                connection_count=len(items),
                destinations=tuple(dict.fromkeys([*current, *history])),
                sent_per_second=rate,
                session_sent=report.session_sent.get(key, 0) if report else None,
                session_received=report.session_received.get(key, 0) if report else None,
            )
        )

    summaries.sort(
        key=lambda s: (
            -(s.session_sent or 0),
            -(s.sent_per_second or 0),
            -s.connection_count,
            s.process_name is None,
            s.process_name or "",
        )
    )
    return tuple(summaries)


def attach_socket_bytes(
    connections: Iterable[Connection], sockets: dict[SocketKey, SocketBytes]
) -> list[Connection]:
    result = []
    for connection in connections:
        counters = None
        if connection.protocol is Protocol.TCP and connection.remote is not None:
            counters = sockets.get((connection.local, connection.remote))
        if counters is not None:
            connection = replace(connection, bytes_sent=counters.sent, bytes_received=counters.received)
        result.append(connection)
    return result


class SnapshotBuilder:
    def __init__(
        self,
        connections: ConnectionCollector | None = None,
        stats: NetworkStatsTracker | None = None,
        now: Callable[[], datetime] = datetime.now,
        sockets: SocketStatsReader | None = None,
        process_traffic: ProcessTrafficTracker | None = None,
        resolver: DomainResolver | None = None,
    ) -> None:
        self._connections = connections or ConnectionCollector()
        self._stats = stats or NetworkStatsTracker()
        self._now = now
        self._sockets = sockets or SocketStatsReader()
        self._process_traffic = process_traffic or ProcessTrafficTracker()
        self._resolver = resolver
        self._first_seen: dict[tuple, datetime] = {}
        self._recent: deque[Connection] = deque(maxlen=RECENT_LIMIT)

    def set_resolver(self, resolver: DomainResolver | None) -> None:
        if self._resolver is not None and self._resolver is not resolver:
            self._resolver.close()
        self._resolver = resolver

    def close(self) -> None:
        self.set_resolver(None)

    def reset_rates(self) -> None:
        self._stats.reset_baseline()
        self._process_traffic.reset_baseline()

    def build(self) -> Snapshot:
        taken_at = self._now()
        traffic = self._stats.sample()
        socket_bytes = self._sockets.read()
        current = self._connections.collect()
        if socket_bytes is not None:
            current = attach_socket_bytes(current, socket_bytes)
        names = self._resolve_names(current)
        if names:
            current = [
                replace(c, remote_name=names[c.remote.ip]) if c.remote and c.remote.ip in names else c
                for c in current
            ]

        first_seen: dict[tuple, datetime] = {}
        connections = []
        for connection in current:
            seen_at = self._first_seen.get(connection.key)
            if seen_at is None:
                seen_at = taken_at
                if connection.is_outbound:
                    self._recent.appendleft(replace(connection, first_seen=taken_at))
            first_seen[connection.key] = seen_at
            connections.append(replace(connection, first_seen=seen_at))
        self._first_seen = first_seen

        report = self._process_traffic.update(connections) if socket_bytes is not None else None
        unattributed_rate = None
        if report is not None and report.attributed_sent_per_second is not None and traffic.sent_per_second is not None:
            unattributed_rate = max(traffic.sent_per_second - report.attributed_sent_per_second, 0.0)

        return Snapshot(
            taken_at=taken_at,
            traffic=traffic,
            connections=tuple(connections),
            outbound_by_process=summarize_outbound(connections, report),
            recent_outbound=tuple(self._recent),
            unattributed_outbound=sum(1 for c in connections if c.is_outbound and c.pid is None),
            unattributed_sent_per_second=unattributed_rate,
            remote_names=names,
        )

    def _resolve_names(self, connections: list[Connection]) -> dict[str, RemoteName]:
        if self._resolver is None:
            return {}
        ips = [c.remote.ip for c in connections if c.is_outbound]
        self._resolver.request(ips)
        names = {}
        for ip in ips:
            name = self._resolver.name_for(ip)
            if name is not None:
                names[ip] = name
        return names
