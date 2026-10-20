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
from netwatch.monitoring.helper_events import HelperState, HelperUpdate
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
        helper: HelperState | None = None,
    ) -> None:
        self._connections = connections or ConnectionCollector()
        self._stats = stats or NetworkStatsTracker()
        self._now = now
        self._sockets = sockets or SocketStatsReader()
        self._process_traffic = process_traffic or ProcessTrafficTracker()
        self._resolver = resolver
        self._helper = helper
        self._first_seen: dict[tuple, datetime] = {}
        self._recent: deque[Connection] = deque(maxlen=RECENT_LIMIT)
        self._started_at: datetime | None = None

    def set_resolver(self, resolver: DomainResolver | None) -> None:
        if self._resolver is not None and self._resolver is not resolver:
            self._resolver.close()
        self._resolver = resolver

    def close(self) -> None:
        self.set_resolver(None)
        if self._helper is not None:
            self._helper.client.close()

    def reset_rates(self) -> None:
        self._stats.reset_baseline()
        self._process_traffic.reset_baseline()

    def build(self) -> Snapshot:
        taken_at = self._now()
        traffic = self._stats.sample()
        socket_bytes = self._sockets.read()
        current = self._connections.collect()
        helper_update = self._helper.drain(taken_at) if self._helper is not None else HelperUpdate((), ())
        if self._helper is not None:
            current = [self._attribute_with_helper(c) for c in current]
        if socket_bytes is not None:
            current = attach_socket_bytes(current, socket_bytes)
        names = self._resolve_names(c.remote.ip for c in (*current, *helper_update.closed) if c.is_outbound)
        if names:
            current = [
                replace(c, remote_name=names[c.remote.ip]) if c.remote and c.remote.ip in names else c
                for c in current
            ]

        first_build = self._started_at is None
        if first_build:
            self._started_at = taken_at
        first_seen: dict[tuple, datetime] = {}
        connections = []
        for connection in current:
            seen_at = self._first_seen.get(connection.key)
            if seen_at is None:
                seen_at = taken_at
                if connection.is_outbound:
                    self._recent.appendleft(replace(connection, first_seen=taken_at, seen_at_start=first_build))
            first_seen[connection.key] = seen_at
            connections.append(
                replace(connection, first_seen=seen_at, seen_at_start=seen_at == self._started_at)
            )
        self._first_seen = first_seen
        closed = tuple(
            replace(c, remote_name=names.get(c.remote.ip)) for c in helper_update.closed if c.is_outbound
        )
        self._add_short_lived_to_recent(helper_update, first_seen)

        report = (
            self._process_traffic.update(connections, closed) if socket_bytes is not None else None
        )
        unattributed_rate = None
        if report is not None and report.attributed_sent_per_second is not None and traffic.sent_per_second is not None:
            unattributed_rate = max(traffic.sent_per_second - report.attributed_sent_per_second, 0.0)

        summaries = summarize_outbound(connections, report)
        displayed = [ip for summary in summaries for ip in summary.destinations]
        displayed += [c.remote.ip for c in self._recent if c.remote]
        names.update(self._resolve_names(ip for ip in displayed if ip not in names))

        return Snapshot(
            taken_at=taken_at,
            traffic=traffic,
            connections=tuple(connections),
            outbound_by_process=summaries,
            recent_outbound=tuple(self._recent),
            unattributed_outbound=sum(1 for c in connections if c.is_outbound and c.pid is None),
            unattributed_sent_per_second=unattributed_rate,
            remote_names=names,
            closed_connections=closed,
            helper_status=self._helper.status() if self._helper is not None else {},
            helper_connected=self._helper is not None and self._helper.client.connected,
        )

    def _attribute_with_helper(self, connection: Connection) -> Connection:
        if connection.pid is not None or connection.remote is None:
            return connection
        process = self._helper.identity_for(connection.local, connection.remote)
        if process is None:
            return connection
        return replace(connection, pid=process.pid, process_name=process.label, process=process)

    def _add_short_lived_to_recent(self, update: HelperUpdate, seen: dict[tuple, datetime]) -> None:
        recent_keys = {(c.local, c.remote) for c in self._recent}
        current_keys = {(key[1], key[2]) for key in seen}
        for connection in (*update.opened, *update.closed):
            key = (connection.local, connection.remote)
            if not connection.is_outbound or key in recent_keys or key in current_keys:
                continue
            recent_keys.add(key)
            self._recent.appendleft(connection)

    def _resolve_names(self, addresses: Iterable[str]) -> dict[str, RemoteName]:
        ips = list(dict.fromkeys(addresses))
        names: dict[str, RemoteName] = {}
        if self._helper is not None:
            for ip in ips:
                name = self._helper.dns.name_for(ip)
                if name is not None:
                    names[ip] = name
        if self._resolver is None:
            return names
        pending = [ip for ip in ips if ip not in names]
        self._resolver.request(pending)
        for ip in pending:
            name = self._resolver.name_for(ip)
            if name is not None:
                names[ip] = name
        return names
