from collections.abc import Callable
from dataclasses import replace

from netwatch.models.connection import ProcessOutbound, Snapshot
from netwatch.models.process import ProcessIdentity
from netwatch.models.signals import Severity, Signal

MEBIBYTE = 1024 * 1024
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
APPIMAGE_MOUNT_PREFIX = "/tmp/.mount_"
NETWORK_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat"})
SCRIPT_TOOL_MIN_SENT = MEBIBYTE
NEW_PROCESS_MEDIUM_SENT = 100 * 1024
UPLOAD_HEAVY_MIN_SENT = 5 * MEBIBYTE
UPLOAD_HEAVY_RATIO = 4

KnownCheck = Callable[[ProcessIdentity], bool | None]


def in_temp_dir(path: str) -> bool:
    return path.startswith(TEMP_PREFIXES) and not path.startswith(APPIMAGE_MOUNT_PREFIX)


def _megabytes(value: int) -> str:
    return f"{value / MEBIBYTE:.1f} MB"


def evaluate(summary: ProcessOutbound, known: bool | None) -> tuple[Signal, ...]:
    process = summary.process
    if process is None:
        return ()
    signals = []
    if process.exe_deleted:
        signals.append(Signal("exe_deleted", Severity.HIGH, "Executável apagado do disco"))

    temp_path = next((path for path in (process.exe, process.script_path) if path and in_temp_dir(path)), None)
    if temp_path:
        signals.append(Signal("temp_dir", Severity.HIGH, f"Rodando de pasta temporária: {temp_path}"))

    sent = summary.session_sent or 0
    received = summary.session_received or 0
    if (process.is_interpreter or process.name in NETWORK_TOOLS) and sent >= SCRIPT_TOOL_MIN_SENT:
        signals.append(
            Signal("script_upload", Severity.MEDIUM, f"Interpretador/ferramenta de rede enviou {_megabytes(sent)}")
        )
    if sent >= UPLOAD_HEAVY_MIN_SENT and sent > UPLOAD_HEAVY_RATIO * received:
        signals.append(
            Signal(
                "upload_heavy",
                Severity.LOW,
                f"Enviou {_megabytes(sent)} e recebeu {_megabytes(received)}",
            )
        )
    if known is False:
        severity = Severity.MEDIUM if sent >= NEW_PROCESS_MEDIUM_SENT else Severity.LOW
        signals.append(Signal("new_process", severity, "Primeira vez fazendo conexões de saída"))
    signals.sort(key=lambda signal: -signal.severity)
    return tuple(signals)


class SignalDetector:
    def __init__(
        self,
        is_known: KnownCheck | None = None,
        learning_until: Callable[[], float | None] | None = None,
    ) -> None:
        self._is_known = is_known
        self._learning_until = learning_until
        self._known: dict[str, bool | None] = {}

    def apply(self, snapshot: Snapshot) -> Snapshot:
        summaries = tuple(
            replace(summary, signals=evaluate(summary, self._known_state(summary.process)))
            for summary in snapshot.outbound_by_process
        )
        learning = self._learning_until() if self._learning_until else None
        return replace(snapshot, outbound_by_process=summaries, learning_until=learning)

    def _known_state(self, process: ProcessIdentity | None) -> bool | None:
        if process is None or self._is_known is None:
            return None
        key = process.group_key
        if key not in self._known:
            self._known[key] = self._is_known(process)
        return self._known[key]


def untrusted_alerts(summaries: tuple[ProcessOutbound, ...], trusted: set[str]) -> list[ProcessOutbound]:
    return [
        summary
        for summary in summaries
        if summary.signals and summary.process is not None and summary.process.group_key not in trusted
    ]
