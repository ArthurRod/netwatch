import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netwatch.models.connection import Protocol
from netwatch.models.history import HistoryEntry, HistoryQuery, ProcessHistory
from netwatch.services.export_service import export_connections, export_processes
from netwatch.services.history_service import HistoryService
from netwatch.ui.plain import PlainLabel
from netwatch.ui.formatting import KNOWN_SERVICES, UNKNOWN, UNKNOWN_PROCESS, format_bytes

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
SEARCH_DEBOUNCE_MS = 300
ALL = "Todos"
DELETED_MARK = " ⚠"

PERIODS = {
    "Última hora": 3600,
    "Últimas 24 horas": 86_400,
    "Últimos 7 dias": 7 * 86_400,
    "Tudo": None,
}
VIEW_CONNECTIONS = "Conexões"
VIEW_PROCESSES = "Por processo"


def format_time(timestamp: float | None) -> str:
    if timestamp is None:
        return UNKNOWN
    moment = datetime.fromtimestamp(timestamp)
    if moment.date() == datetime.now().date():
        return moment.strftime("%H:%M:%S")
    return moment.strftime("%d/%m %H:%M:%S")


def history_process_label(entry: HistoryEntry) -> str:
    if entry.process_label is None:
        service = KNOWN_SERVICES.get((entry.protocol, entry.remote_port))
        label = f"{UNKNOWN_PROCESS} · {service}" if service else UNKNOWN_PROCESS
    else:
        label = entry.process_label
    return label + (DELETED_MARK if entry.exe_deleted else "")


def _history_name(entry: HistoryEntry) -> str:
    if entry.remote_name is None:
        return UNKNOWN
    return entry.remote_name if entry.remote_name_confirmed else f"{entry.remote_name}?"


def _start_text(entry: HistoryEntry) -> str:
    text = format_time(entry.first_seen)
    return f"antes de {text}" if entry.seen_at_start else text


def _process_start_text(process: ProcessHistory) -> str:
    text = format_time(process.first_seen)
    return f"antes de {text}" if process.first_seen_at_start else text


def _end_text(entry: HistoryEntry) -> str:
    if entry.closed_at is not None:
        return format_time(entry.closed_at)
    return f"visto {format_time(entry.last_seen)}"


def _number(value: int | None) -> int:
    return value if value is not None else -1


@dataclass(frozen=True, slots=True)
class Column:
    header: str
    display: Callable[[Any], str]
    sort: Callable[[Any], Any] | None = None


CONNECTION_COLUMNS = (
    Column("Início", _start_text, lambda e: e.first_seen),
    Column("Fim", _end_text, lambda e: e.closed_at or e.last_seen),
    Column("Processo", history_process_label),
    Column("PID", lambda e: str(e.pid) if e.pid is not None else UNKNOWN, lambda e: _number(e.pid)),
    Column("Destino", lambda e: e.remote_ip),
    Column("Domínio", _history_name),
    Column("Porta", lambda e: str(e.remote_port), lambda e: e.remote_port),
    Column("Protocolo", lambda e: e.protocol.value),
    Column("Enviado", lambda e: format_bytes(e.bytes_sent), lambda e: _number(e.bytes_sent)),
    Column("Recebido", lambda e: format_bytes(e.bytes_received), lambda e: _number(e.bytes_received)),
    Column("Comando", lambda e: e.command or UNKNOWN),
)

PROCESS_COLUMNS = (
    Column(
        "Processo",
        lambda p: (p.process_label or UNKNOWN_PROCESS) + (DELETED_MARK if p.exe_deleted else ""),
    ),
    Column("Enviado", lambda p: format_bytes(p.bytes_sent), lambda p: _number(p.bytes_sent)),
    Column("Recebido", lambda p: format_bytes(p.bytes_received), lambda p: _number(p.bytes_received)),
    Column("Conexões", lambda p: str(p.connection_count), lambda p: p.connection_count),
    Column("Destinos", lambda p: str(p.destination_count), lambda p: p.destination_count),
    Column("Primeira vez", _process_start_text, lambda p: p.first_seen),
    Column("Última vez", lambda p: format_time(p.last_seen), lambda p: p.last_seen),
    Column("Executável", lambda p: p.exe or UNKNOWN),
)


class RecordTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._columns: tuple[Column, ...] = CONNECTION_COLUMNS
        self._rows: list[Any] = []

    def set_records(self, columns: tuple[Column, ...], rows: list[Any]) -> None:
        self.beginResetModel()
        self._columns = columns
        self._rows = rows
        self.endResetModel()

    def records(self) -> list[Any]:
        return self._rows

    def record_at(self, row: int) -> Any:
        return self._rows[row]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._columns)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        column = self._columns[index.column()]
        record = self._rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return column.display(record)
        if role == SORT_ROLE:
            return column.sort(record) if column.sort else column.display(record).lower()
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._columns[section].header
        return None


def describe_entry(entry: HistoryEntry) -> str:
    exe = entry.exe or UNKNOWN
    if entry.exe_deleted:
        exe = f"{exe}  ⚠ apagado do disco"
    lines = [
        f"{entry.protocol.value} → {entry.remote_ip}:{entry.remote_port} · início {_start_text(entry)} · fim {_end_text(entry)}",
        f"Nome reverso: {_history_name(entry)}"
        + ("" if entry.remote_name is None else " (confirmado)" if entry.remote_name_confirmed else " (não confirmado)"),
        f"Comando: {entry.command or UNKNOWN}",
        f"Executável: {exe}",
        f"Usuário: {entry.username or UNKNOWN} · PID {entry.pid if entry.pid is not None else UNKNOWN}",
        f"Iniciado por: {entry.lineage or UNKNOWN}",
    ]
    return "\n".join(lines)


def describe_process(process: ProcessHistory) -> str:
    exe = process.exe or UNKNOWN
    if process.exe_deleted:
        exe = f"{exe}  ⚠ apagado do disco"
    return "\n".join(
        [
            f"{process.process_label or UNKNOWN_PROCESS}: {process.connection_count} conexões para "
            f"{process.destination_count} destinos, {format_bytes(process.bytes_sent)} enviados",
            f"Comando (exemplo): {process.command or UNKNOWN}",
            f"Executável: {exe}",
        ]
    )


class HistoryTab(QWidget):
    def __init__(self, service: HistoryService) -> None:
        super().__init__()
        self._service = service

        self._view = QComboBox()
        self._view.addItems([VIEW_PROCESSES, VIEW_CONNECTIONS])
        self._period = QComboBox()
        self._period.addItems(list(PERIODS))
        self._period.setCurrentText("Últimas 24 horas")
        self._protocol = QComboBox()
        self._protocol.addItems([ALL, Protocol.TCP.value, Protocol.UDP.value])
        self._search = QLineEdit(placeholderText="Buscar processo, comando, caminho, IP, domínio ou PID")
        refresh = QPushButton("Atualizar")
        export = QPushButton("Exportar CSV")
        clear = QPushButton("Apagar histórico")

        self._debounce = QTimer(self, singleShot=True, interval=SEARCH_DEBOUNCE_MS)
        self._debounce.timeout.connect(self.refresh)
        self._search.textChanged.connect(self._debounce.start)
        for combo in (self._view, self._period, self._protocol):
            combo.currentTextChanged.connect(self.refresh)
        refresh.clicked.connect(self.refresh)
        export.clicked.connect(self._export)
        clear.clicked.connect(self._confirm_clear)

        filters = QHBoxLayout()
        filters.addWidget(PlainLabel("Ver"))
        filters.addWidget(self._view)
        filters.addWidget(self._period)
        filters.addWidget(PlainLabel("Protocolo"))
        filters.addWidget(self._protocol)
        filters.addWidget(self._search, 1)
        filters.addWidget(refresh)
        filters.addWidget(export)
        filters.addWidget(clear)

        self._model = RecordTableModel()
        self._proxy = QSortFilterProxyModel()
        self._proxy.setSortRole(SORT_ROLE)
        self._proxy.setSourceModel(self._model)
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self._inspector = PlainLabel()
        self._inspector.setWordWrap(True)
        self._inspector.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._inspector.setStyleSheet("font-family: monospace; padding: 6px; background-color: #1a1e29;")
        self._status = PlainLabel()

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._inspector)
        layout.addWidget(self._status)

        service.connections_ready.connect(self._on_connections)
        service.processes_ready.connect(self._on_processes)
        service.cleared.connect(self._on_cleared)
        service.failed.connect(self._on_failed)

    def _query(self) -> HistoryQuery:
        seconds = PERIODS[self._period.currentText()]
        protocol = self._protocol.currentText()
        return HistoryQuery(
            since=time.time() - seconds if seconds is not None else None,
            search=self._search.text(),
            protocol=None if protocol == ALL else Protocol(protocol),
        )

    def refresh(self) -> None:
        self._status.setText("Consultando…")
        if self._view.currentText() == VIEW_PROCESSES:
            self._service.query_processes(self._query())
        else:
            self._service.query_connections(self._query())

    def _on_connections(self, entries: list[HistoryEntry]) -> None:
        if self._view.currentText() != VIEW_CONNECTIONS:
            return
        self._show(CONNECTION_COLUMNS, entries, 0)
        self._status.setText(f"{len(entries)} conexões · limite de {HistoryQuery().limit} por consulta")

    def _on_processes(self, processes: list[ProcessHistory]) -> None:
        if self._view.currentText() != VIEW_PROCESSES:
            return
        self._show(PROCESS_COLUMNS, processes, 1)
        self._status.setText(
            f"{len(processes)} processos · bytes = soma do último valor observado de cada conexão TCP"
        )

    def _show(self, columns: tuple[Column, ...], rows: list[Any], sort_column: int) -> None:
        self._model.set_records(columns, rows)
        self._table.sortByColumn(sort_column, Qt.SortOrder.DescendingOrder)
        self._inspector.setText("Selecione uma linha para ver o processo.")

    def _on_selection_changed(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        record = self._model.record_at(self._proxy.mapToSource(rows[0]).row())
        self._inspector.setText(describe_entry(record) if isinstance(record, HistoryEntry) else describe_process(record))

    def _export(self) -> None:
        records = self._model.records()
        if not records:
            self._status.setText("Nada para exportar.")
            return
        name = f"netwatch-{datetime.now():%Y%m%d-%H%M%S}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "Exportar CSV", str(Path.home() / name), "CSV (*.csv)")
        if not path:
            return
        try:
            if isinstance(records[0], HistoryEntry):
                export_connections(records, Path(path))
            else:
                export_processes(records, Path(path))
        except OSError as error:
            self._status.setText(f"Falha ao exportar: {error}")
            return
        self._status.setText(f"{len(records)} linhas exportadas para {path}")

    def _confirm_clear(self) -> None:
        answer = QMessageBox.question(
            self,
            "Apagar histórico",
            "Apagar todo o histórico de conexões? Isso não pode ser desfeito.",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._status.setText("Apagando…")
            self._service.clear()

    def _on_cleared(self) -> None:
        self._status.setText("Histórico apagado.")
        self.refresh()

    def _on_failed(self, message: str) -> None:
        self._status.setText(f"Erro no histórico: {message}")
