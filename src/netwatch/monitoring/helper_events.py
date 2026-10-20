import pwd
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from netwatch.models.connection import Connection, Endpoint, Protocol, normalize_ip
from netwatch.models.domain import NameSource, RemoteName
from netwatch.models.process import ProcessIdentity, redact_arguments
from netwatch.services.helper_client import HelperClient

DNS_NAME_TTL_SECONDS = 3600
MAX_DNS_ADDRESSES = 20_000
MAX_TRACKED_SOCKETS = 65_536
CLOSED_STATUS_LABEL = "CLOSED"

SocketKey = tuple[Endpoint, Endpoint]


def _username(uid: object) -> str | None:
    if not isinstance(uid, int):
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def identity_from_helper(data: object, fallback_pid: object = None, fallback_name: object = None) -> ProcessIdentity | None:
    if isinstance(data, dict) and isinstance(data.get("pid"), int) and isinstance(data.get("name"), str):
        ancestors = tuple(
            (int(item[0]), str(item[1]))
            for item in data.get("ancestors") or ()
            if isinstance(item, list) and len(item) == 2 and isinstance(item[0], int)
        )
        return ProcessIdentity(
            pid=data["pid"],
            name=data["name"],
            exe=data["exe"] if isinstance(data.get("exe"), str) else None,
            exe_deleted=bool(data.get("exe_deleted")),
            cmdline=redact_arguments(tuple(str(part) for part in data.get("cmdline") or ())),
            username=_username(data.get("uid")),
            ancestors=ancestors,
            cwd=data["cwd"] if isinstance(data.get("cwd"), str) else None,
        )
    if isinstance(fallback_pid, int) and fallback_pid > 0 and isinstance(fallback_name, str) and fallback_name:
        return ProcessIdentity(fallback_pid, fallback_name, None, False, (), None, ())
    return None


def _endpoint(value: object) -> Endpoint | None:
    if not isinstance(value, list) or len(value) != 2:
        return None
    ip, port = value
    if not isinstance(ip, str) or not isinstance(port, int):
        return None
    return Endpoint(normalize_ip(ip), port)


class DnsNameTable:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._names: dict[str, dict[str, float]] = {}

    def ingest(self, event: dict) -> None:
        answers = event.get("answers")
        if not isinstance(answers, dict):
            return
        questions = [q for q in event.get("questions") or () if isinstance(q, str) and q]
        now = self._clock()
        for record_name, addresses in answers.items():
            if not isinstance(addresses, list):
                continue
            labels = questions or [record_name]
            for address in addresses:
                if not isinstance(address, str):
                    continue
                known = self._names.setdefault(normalize_ip(address), {})
                for label in labels:
                    known[label] = now
        if len(self._names) > MAX_DNS_ADDRESSES:
            self._prune(now)

    def name_for(self, ip: str) -> RemoteName | None:
        known = self._names.get(ip)
        if not known:
            return None
        cutoff = self._clock() - DNS_NAME_TTL_SECONDS
        recent = sorted((name for name, seen in known.items() if seen >= cutoff), key=lambda n: -known[n])
        if not recent:
            return None
        if len(recent) == 1:
            return RemoteName(recent[0], NameSource.DNS_OBSERVED)
        return RemoteName(recent[0], NameSource.DNS_AMBIGUOUS, tuple(recent[1:]))

    def _prune(self, now: float) -> None:
        cutoff = now - DNS_NAME_TTL_SECONDS
        self._names = {
            ip: fresh
            for ip, names in self._names.items()
            if (fresh := {name: seen for name, seen in names.items() if seen >= cutoff})
        }
        while len(self._names) > MAX_DNS_ADDRESSES:
            self._names.pop(next(iter(self._names)))


@dataclass(frozen=True, slots=True)
class HelperUpdate:
    opened: tuple[Connection, ...]
    closed: tuple[Connection, ...]


class HelperState:
    def __init__(self, client: HelperClient, dns: DnsNameTable | None = None) -> None:
        self.client = client
        self.dns = dns or DnsNameTable()
        self._sockets: dict[SocketKey, ProcessIdentity | None] = {}

    @property
    def active(self) -> bool:
        return self.client.connected and self.client.status().get("tcp") == "running"

    def status(self) -> dict[str, str]:
        if not self.client.connected:
            return {}
        return self.client.status()

    def identity_for(self, local: Endpoint, remote: Endpoint) -> ProcessIdentity | None:
        return self._sockets.get((local, remote))

    def drain(self, now: datetime) -> HelperUpdate:
        opened = []
        closed = []
        for event in self.client.drain():
            kind = event.get("type")
            if kind == "dns":
                self.dns.ingest(event)
            elif kind in ("tcp_connect", "tcp_close"):
                connection = self._connection(event, now)
                if connection is None:
                    continue
                key = (connection.local, connection.remote)
                if kind == "tcp_connect":
                    if len(self._sockets) >= MAX_TRACKED_SOCKETS:
                        self._sockets.clear()
                    self._sockets[key] = connection.process
                    opened.append(connection)
                else:
                    self._sockets.pop(key, None)
                    closed.append(connection)
        return HelperUpdate(tuple(opened), tuple(closed))

    def _connection(self, event: dict, now: datetime) -> Connection | None:
        local = _endpoint(event.get("local"))
        remote = _endpoint(event.get("remote"))
        if local is None or remote is None:
            return None
        process = identity_from_helper(event.get("process"), event.get("pid"), event.get("comm"))
        if process is None and event.get("type") == "tcp_close":
            process = self._sockets.get((local, remote))
        sent = event.get("bytes_sent")
        received = event.get("bytes_received")
        return Connection(
            protocol=Protocol.TCP,
            local=local,
            remote=remote,
            status=CLOSED_STATUS_LABEL if event.get("type") == "tcp_close" else "SYN_SENT",
            pid=process.pid if process else None,
            process_name=process.label if process else None,
            first_seen=now,
            bytes_sent=sent if isinstance(sent, int) else None,
            bytes_received=received if isinstance(received, int) else None,
            process=process,
        )
