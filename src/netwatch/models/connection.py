import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from netwatch.models.domain import RemoteName
from netwatch.models.process import ProcessIdentity
from netwatch.models.signals import Severity, Signal

CLOSED_STATUS = "TIME_WAIT"


class Protocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"


@dataclass(frozen=True, slots=True)
class Endpoint:
    ip: str
    port: int


@dataclass(frozen=True, slots=True)
class Connection:
    protocol: Protocol
    local: Endpoint
    remote: Endpoint | None
    status: str | None
    pid: int | None
    process_name: str | None
    first_seen: datetime | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    process: ProcessIdentity | None = None
    remote_is_local: bool = False
    remote_name: RemoteName | None = None
    seen_at_start: bool = False

    @property
    def group_key(self) -> str | None:
        return self.process.group_key if self.process else self.process_name

    @property
    def key(self) -> tuple:
        return (self.protocol, self.local, self.remote, self.pid)

    @property
    def is_closed(self) -> bool:
        return self.status == CLOSED_STATUS

    @property
    def is_outbound(self) -> bool:
        return (
            self.remote is not None
            and not self.is_closed
            and not self.remote_is_local
            and is_external_ip(self.remote.ip)
        )


def normalize_ip(ip: str) -> str:
    bare = ip.split("%", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(bare).compressed
    except ValueError:
        return bare


def is_external_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return not (address.is_loopback or address.is_unspecified)


@dataclass(frozen=True, slots=True)
class TrafficStats:
    sent_per_second: float | None
    received_per_second: float | None
    session_sent: int
    session_received: int
    interfaces: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProcessOutbound:
    process_name: str | None
    process: ProcessIdentity | None
    connection_count: int
    destinations: tuple[str, ...]
    sent_per_second: float | None = None
    session_sent: int | None = None
    session_received: int | None = None
    signals: tuple[Signal, ...] = ()

    @property
    def severity(self) -> Severity | None:
        return max((signal.severity for signal in self.signals), default=None)


@dataclass(frozen=True, slots=True)
class Snapshot:
    taken_at: datetime
    traffic: TrafficStats
    connections: tuple[Connection, ...]
    outbound_by_process: tuple[ProcessOutbound, ...]
    recent_outbound: tuple[Connection, ...]
    unattributed_outbound: int
    unattributed_sent_per_second: float | None = None
    learning_until: float | None = None
    remote_names: dict[str, RemoteName] = field(default_factory=dict)
    closed_connections: tuple[Connection, ...] = ()
    helper_status: dict[str, str] = field(default_factory=dict)

    @property
    def helper_active(self) -> bool:
        return self.helper_status.get("tcp") == "running"

    @property
    def outbound_count(self) -> int:
        return sum(1 for connection in self.connections if connection.is_outbound)
