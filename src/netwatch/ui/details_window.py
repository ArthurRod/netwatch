from datetime import datetime, timedelta

from PySide6.QtCore import QItemSelectionModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from netwatch.models.connection import Connection, Protocol, Snapshot
from netwatch.services.history_service import HistoryService
from netwatch.ui.connection_table import ConnectionFilterProxy, ConnectionTableModel
from netwatch.ui.formatting import (
    connection_process_label,
    format_endpoint,
    format_remote_name,
    process_details,
    remote_name_note,
)
from netwatch.ui.alerts_tab import AlertsTab
from netwatch.ui.history_tab import HistoryTab
from netwatch.ui.plain import PlainLabel
from netwatch.ui.theme import WINDOW_STYLESHEET

ALL = "Todos"
NEW_WINDOW_MINUTES = 5


class DetailsWindow(QWidget):
    def __init__(self, history: HistoryService) -> None:
        super().__init__()
        self.setWindowTitle("NetWatch — Conexões")
        self.setStyleSheet(WINDOW_STYLESHEET)
        self.resize(980, 520)

        self._model = ConnectionTableModel()
        self._proxy = ConnectionFilterProxy()
        self._proxy.setSourceModel(self._model)

        self._search = QLineEdit(placeholderText="Buscar processo, IP, PID, comando ou caminho")
        self._search.textChanged.connect(self._proxy.set_search)
        self._protocol = QComboBox()
        self._protocol.addItems([ALL, Protocol.TCP.value, Protocol.UDP.value])
        self._protocol.currentTextChanged.connect(self._on_protocol_changed)
        self._process = QComboBox()
        self._process.addItem(ALL)
        self._process.currentTextChanged.connect(self._on_process_changed)
        self._outbound_only = QCheckBox("Somente saída")
        self._outbound_only.setChecked(True)
        self._outbound_only.toggled.connect(self._proxy.set_outbound_only)
        self._new_only = QCheckBox(f"Somente novas ({NEW_WINDOW_MINUTES} min)")
        self._new_only.setToolTip("Conexões que apareceram nos últimos minutos e não estavam abertas quando o NetWatch iniciou")
        self._new_only.toggled.connect(self._apply_new_filter)
        self._frozen = QCheckBox("Congelar")
        self._frozen.setToolTip("Para de atualizar a tabela enquanto você investiga")

        filters = QHBoxLayout()
        filters.addWidget(self._search, 2)
        filters.addWidget(PlainLabel("Protocolo"))
        filters.addWidget(self._protocol)
        filters.addWidget(PlainLabel("Processo"))
        filters.addWidget(self._process, 1)
        filters.addWidget(self._outbound_only)
        filters.addWidget(self._new_only)
        filters.addWidget(self._frozen)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)

        self._selected_key: tuple | None = None
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self._inspector = PlainLabel("Selecione uma conexão para ver o processo de origem.")
        self._inspector.setObjectName("inspector")
        self._inspector.setWordWrap(True)
        self._inspector.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._inspector.setStyleSheet("font-family: monospace; padding: 6px; background-color: #1a1e29;")

        self._footer = PlainLabel()
        self._footer.setObjectName("muted")
        notice = PlainLabel(
            "“—” = valor desconhecido. Domínio = nome reverso (PTR), “?” = não confirmado; bytes só para TCP; "
            "“sem permissão” = processo de outro usuário; “encerrada” = TIME_WAIT, já fechada pelo processo."
        )
        notice.setWordWrap(True)

        live = QWidget()
        layout = QVBoxLayout(live)
        layout.addLayout(filters)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._inspector)
        layout.addWidget(notice)
        layout.addWidget(self._footer)

        self._history = HistoryTab(history)
        self.alerts = AlertsTab()
        self._tabs = QTabWidget()
        self._tabs.addTab(live, "Agora")
        self._tabs.addTab(self.alerts, "Alertas")
        self._tabs.addTab(self._history, "Histórico")
        self._tabs.currentChanged.connect(self._on_tab_changed)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._tabs)

    def show_alerts(self) -> None:
        self._tabs.setCurrentWidget(self.alerts)

    def _on_tab_changed(self, index: int) -> None:
        if self._tabs.widget(index) is self._history:
            self._history.refresh()

    def _apply_new_filter(self) -> None:
        since = datetime.now() - timedelta(minutes=NEW_WINDOW_MINUTES) if self._new_only.isChecked() else None
        self._proxy.set_new_since(since)

    def _on_protocol_changed(self, text: str) -> None:
        self._proxy.set_protocol(None if text == ALL else Protocol(text))

    def _on_process_changed(self, text: str) -> None:
        self._proxy.set_process(None if text in (ALL, "") else text)

    def update_snapshot(self, snapshot: Snapshot) -> None:
        self.alerts.update_snapshot(snapshot)
        if self._frozen.isChecked() or not self.isVisible():
            return
        self._model.set_connections(list(snapshot.connections))
        if self._new_only.isChecked():
            self._apply_new_filter()
        self._restore_selection()
        self._refresh_process_options(snapshot)
        self._footer.setText(
            f"{len(snapshot.connections)} sockets · {snapshot.outbound_count} de saída · "
            f"atualizado às {snapshot.taken_at:%H:%M:%S}"
        )

    def _selected_connection(self) -> Connection | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        return self._model.connection_at(self._proxy.mapToSource(rows[0]).row())

    def _on_selection_changed(self) -> None:
        connection = self._selected_connection()
        if connection is None:
            return
        self._selected_key = connection.key
        self._show_connection(connection)

    def _restore_selection(self) -> None:
        if self._selected_key is None:
            return
        row = self._model.row_of(self._selected_key)
        if row is None:
            self._inspector.setText(f"{self._inspector.text()}\n\n(conexão encerrada)")
            self._selected_key = None
            return
        index = self._proxy.mapFromSource(self._model.index(row, 0))
        if not index.isValid():
            return
        self._table.selectionModel().select(
            index,
            QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows,
        )

    def _show_connection(self, connection: Connection) -> None:
        header = (
            f"{connection.protocol.value} {format_endpoint(connection.local)} → "
            f"{format_endpoint(connection.remote)} · {connection.status or '—'}"
        )
        name = f"Nome: {format_remote_name(connection.remote_name)}"
        note = remote_name_note(connection.remote_name)
        if note:
            name = f"{name}  ({note})"
        self._inspector.setText(f"{header}\n{name}\n{process_details(connection.process)}")

    def _refresh_process_options(self, snapshot: Snapshot) -> None:
        names = sorted({connection_process_label(c) for c in snapshot.connections})
        current = self._process.currentText()
        existing = [self._process.itemText(i) for i in range(1, self._process.count())]
        if names == existing:
            return
        self._process.blockSignals(True)
        self._process.clear()
        self._process.addItems([ALL, *names])
        if current in names:
            self._process.setCurrentText(current)
        self._process.blockSignals(False)
        if current not in (ALL, *names):
            self._on_process_changed(ALL)
