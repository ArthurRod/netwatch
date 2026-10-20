from dataclasses import dataclass

from netwatch.models.connection import Protocol


@dataclass(frozen=True, slots=True)
class HistoryQuery:
    since: float | None = None
    search: str = ""
    protocol: Protocol | None = None
    limit: int = 2000


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    id: int
    first_seen: float
    seen_at_start: bool
    last_seen: float
    closed_at: float | None
    protocol: Protocol
    remote_ip: str
    remote_port: int
    status: str | None
    pid: int | None
    process_label: str | None
    exe: str | None
    exe_deleted: bool
    command: str | None
    username: str | None
    lineage: str | None
    bytes_sent: int | None
    bytes_received: int | None
    remote_name: str | None = None
    remote_name_confirmed: bool = False


@dataclass(frozen=True, slots=True)
class ProcessHistory:
    process_label: str | None
    exe: str | None
    command: str | None
    connection_count: int
    destination_count: int
    bytes_sent: int | None
    bytes_received: int | None
    first_seen: float
    first_seen_at_start: bool
    last_seen: float
    exe_deleted: bool
