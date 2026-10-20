import csv
import os
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from netwatch.models.history import HistoryEntry, ProcessHistory

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CONNECTION_HEADER = (
    "inicio",
    "aberta_antes_do_monitoramento",
    "visto_por_ultimo",
    "encerrada_em",
    "processo",
    "pid",
    "usuario",
    "comando",
    "executavel",
    "executavel_apagado",
    "iniciado_por",
    "protocolo",
    "destino",
    "nome_reverso",
    "nome_reverso_confirmado",
    "porta",
    "estado",
    "bytes_enviados",
    "bytes_recebidos",
)

PROCESS_HEADER = (
    "processo",
    "executavel",
    "comando",
    "conexoes",
    "destinos_distintos",
    "bytes_enviados",
    "bytes_recebidos",
    "primeira_vez",
    "ja_aberta_na_primeira_vez",
    "ultima_vez",
    "executavel_apagado",
)


def safe_cell(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def _time(timestamp: float | None) -> str:
    return datetime.fromtimestamp(timestamp).isoformat(timespec="seconds") if timestamp is not None else ""


def _write(path: Path, header: tuple[str, ...], rows: Iterable[tuple]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(header)
        for row in rows:
            writer.writerow([safe_cell(value) for value in row])


def export_connections(entries: Iterable[HistoryEntry], path: Path) -> None:
    _write(
        path,
        CONNECTION_HEADER,
        (
            (
                _time(e.first_seen),
                "sim" if e.seen_at_start else "nao",
                _time(e.last_seen),
                _time(e.closed_at),
                e.process_label,
                e.pid,
                e.username,
                e.command,
                e.exe,
                "sim" if e.exe_deleted else "nao",
                e.lineage,
                e.protocol.value,
                e.remote_ip,
                e.remote_name,
                ("sim" if e.remote_name_confirmed else "nao") if e.remote_name else "",
                e.remote_port,
                e.status,
                e.bytes_sent,
                e.bytes_received,
            )
            for e in entries
        ),
    )


def export_processes(entries: Iterable[ProcessHistory], path: Path) -> None:
    _write(
        path,
        PROCESS_HEADER,
        (
            (
                p.process_label,
                p.exe,
                p.command,
                p.connection_count,
                p.destination_count,
                p.bytes_sent,
                p.bytes_received,
                _time(p.first_seen),
                "sim" if p.first_seen_at_start else "nao",
                _time(p.last_seen),
                "sim" if p.exe_deleted else "nao",
            )
            for p in entries
        ),
    )
