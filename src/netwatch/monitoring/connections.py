import os
import socket
from dataclasses import replace
from collections.abc import Callable, Iterable
from typing import Any

import psutil

from netwatch.models.connection import Connection, Endpoint, Protocol, normalize_ip
from netwatch.models.process import ProcessIdentity, redact_arguments

ConnectionReader = Callable[[], Iterable[Any]]

ANCESTOR_LIMIT = 4
DELETED_SUFFIX = " (deleted)"


def read_psutil_connections() -> list[Any]:
    return psutil.net_connections(kind="inet")


def read_local_addresses() -> set[str]:
    return {
        normalize_ip(address.address)
        for addresses in psutil.net_if_addrs().values()
        for address in addresses
        if address.family in (socket.AF_INET, socket.AF_INET6)
    }


def normalize_connection(raw: Any, process: ProcessIdentity | None) -> Connection | None:
    if raw.type == socket.SOCK_STREAM:
        protocol = Protocol.TCP
    elif raw.type == socket.SOCK_DGRAM:
        protocol = Protocol.UDP
    else:
        return None

    status = raw.status if raw.status and raw.status != psutil.CONN_NONE else None
    return Connection(
        protocol=protocol,
        local=Endpoint(normalize_ip(raw.laddr.ip), raw.laddr.port),
        remote=Endpoint(normalize_ip(raw.raddr.ip), raw.raddr.port) if raw.raddr else None,
        status=status,
        pid=raw.pid,
        process_name=process.label if process else None,
        process=process,
    )


class ProcessCache:
    def __init__(self, lookup: Callable[[int], ProcessIdentity | None] | None = None) -> None:
        self._lookup = lookup or lookup_process
        self._processes: dict[int, ProcessIdentity | None] = {}

    def get(self, pid: int | None) -> ProcessIdentity | None:
        if pid is None:
            return None
        if pid not in self._processes:
            self._processes[pid] = self._lookup(pid)
        return self._processes[pid]

    def retain(self, pids: set[int]) -> None:
        self._processes = {pid: process for pid, process in self._processes.items() if pid in pids}


def lookup_process(pid: int) -> ProcessIdentity | None:
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            name = process.name()
            exe = _optional(process.exe) or None
            cmdline = tuple(_optional(process.cmdline) or ())
            username = _optional(process.username)
            cwd = _optional(process.cwd)
        ancestors = tuple((parent.pid, _optional(parent.name) or "?") for parent in process.parents()[:ANCESTOR_LIMIT])
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    return ProcessIdentity(
        pid=pid,
        name=name,
        exe=exe,
        exe_deleted=_exe_deleted(pid),
        cmdline=redact_arguments(cmdline),
        username=username,
        ancestors=ancestors,
        cwd=cwd,
    )


def _optional(getter: Callable[[], Any]) -> Any:
    try:
        return getter()
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
        return None


def _exe_deleted(pid: int) -> bool:
    try:
        return os.readlink(f"/proc/{pid}/exe").endswith(DELETED_SUFFIX)
    except OSError:
        return False


class ConnectionCollector:
    def __init__(
        self,
        read_connections: ConnectionReader = read_psutil_connections,
        processes: ProcessCache | None = None,
        read_local_addresses: Callable[[], set[str]] = read_local_addresses,
    ) -> None:
        self._read_connections = read_connections
        self._read_local_addresses = read_local_addresses
        self._processes = processes or ProcessCache()

    def collect(self) -> list[Connection]:
        try:
            raw_connections = list(self._read_connections())
        except psutil.AccessDenied:
            return []

        local_addresses = self._read_local_addresses()
        connections = []
        for raw in raw_connections:
            connection = normalize_connection(raw, self._processes.get(raw.pid))
            if connection is None:
                continue
            if connection.remote is not None and connection.remote.ip in local_addresses:
                connection = replace(connection, remote_is_local=True)
            connections.append(connection)

        self._processes.retain({c.pid for c in connections if c.pid is not None})
        return connections
