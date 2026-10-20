import logging
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from netwatch.models.connection import Endpoint, normalize_ip

logger = logging.getLogger(__name__)

SS_COMMAND = ("ss", "-tinHn")
SS_TIMEOUT_SECONDS = 2
_BYTE_FIELDS = re.compile(r"\b(bytes_acked|bytes_received):(\d+)")


@dataclass(frozen=True, slots=True)
class SocketBytes:
    sent: int
    received: int


SocketKey = tuple[Endpoint, Endpoint]


def parse_endpoint(text: str) -> Endpoint | None:
    host, separator, port = text.rpartition(":")
    if not separator or not port.isdigit():
        return None
    return Endpoint(normalize_ip(host), int(port))


def parse_ss(output: str) -> dict[SocketKey, SocketBytes]:
    sockets: dict[SocketKey, SocketBytes] = {}
    key: SocketKey | None = None
    for line in output.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            local = parse_endpoint(parts[3]) if len(parts) >= 5 else None
            remote = parse_endpoint(parts[4]) if len(parts) >= 5 else None
            key = (local, remote) if local and remote else None
            continue
        if key is None:
            continue
        fields = dict(_BYTE_FIELDS.findall(line))
        sockets[key] = SocketBytes(
            sent=int(fields.get("bytes_acked", 0)),
            received=int(fields.get("bytes_received", 0)),
        )
        key = None
    return sockets


def run_ss() -> str:
    completed = subprocess.run(
        SS_COMMAND, capture_output=True, text=True, timeout=SS_TIMEOUT_SECONDS, check=True
    )
    return completed.stdout


class SocketStatsReader:
    def __init__(self, run: Callable[[], str] = run_ss) -> None:
        self._run = run
        self._warned = False

    def read(self) -> dict[SocketKey, SocketBytes] | None:
        try:
            output = self._run()
        except (OSError, subprocess.SubprocessError) as error:
            if not self._warned:
                logger.warning("Per-socket byte counters unavailable (ss failed): %s", error)
                self._warned = True
            return None
        return parse_ss(output)
