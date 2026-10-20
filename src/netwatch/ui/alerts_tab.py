from datetime import datetime

from PySide6.QtCore import QSortFilterProxyModel, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netwatch.models.connection import ProcessOutbound, Snapshot
from netwatch.models.signals import SEVERITY_LABELS
from netwatch.ui.formatting import UNKNOWN, format_bytes, process_details
from netwatch.ui.history_tab import SORT_ROLE, Column, RecordTableModel
from netwatch.ui.plain import PlainLabel

TRUST = "Confiar neste processo"
UNTRUST = "Remover confiança"


def _source(summary: ProcessOutbound) -> str:
    process = summary.process
    return (process.script_path or process.exe or UNKNOWN) if process else UNKNOWN


class AlertsTab(QWidget):
    trust_toggled = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._trusted: set[str] = set()
        self._selected_key: str | None = None
        self._columns = (
            Column("Severidade", lambda s: SEVERITY_LABELS[s.severity], lambda s: s.severity),
            Column("Processo", lambda s: s.process_name or UNKNOWN),
            Column("Sinais", lambda s: " · ".join(signal.message for signal in s.signals)),
            Column("Enviado", lambda s: format_bytes(s.session_sent), lambda s: s.session_sent or 0),
            Column("Origem", _source),
            Column("Confiável", lambda s: "sim" if self._key(s) in self._trusted else "não"),
        )

        self._learning = PlainLabel()
        self._learning.setWordWrap(True)
        self._model = RecordTableModel()
        self._proxy = QSortFilterProxyModel()
        self._proxy.setSortRole(SORT_ROLE)
        self._proxy.setSourceModel(self._model)
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self._inspector = PlainLabel("Selecione um processo para ver os detalhes.")
        self._inspector.setWordWrap(True)
        self._inspector.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._inspector.setStyleSheet("font-family: monospace; padding: 6px; background-color: #1a1e29;")
        self._trust = QPushButton(TRUST)
        self._trust.setEnabled(False)
        self._trust.clicked.connect(self._on_trust_clicked)
        notice = PlainLabel(
            "Sinais são heurísticas: indicam o que merece um olhar, não provam que algo é malicioso. "
            "Confiar num processo (executável + script) para de destacá-lo e de notificar, mas ele continua listado aqui."
        )
        notice.setWordWrap(True)

        actions = QHBoxLayout()
        actions.addWidget(self._learning, 1)
        actions.addWidget(self._trust)
        layout = QVBoxLayout(self)
        layout.addLayout(actions)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._inspector)
        layout.addWidget(notice)

    @staticmethod
    def _key(summary: ProcessOutbound) -> str | None:
        return summary.process.group_key if summary.process else None

    def set_trusted(self, trusted: set[str]) -> None:
        self._trusted = trusted
        self._model.set_records(self._columns, self._model.records())
        self._restore_selection()
        self._refresh_trust_button()

    def update_snapshot(self, snapshot: Snapshot) -> None:
        if not self.isVisible():
            return
        alerts = [summary for summary in snapshot.outbound_by_process if summary.signals]
        self._model.set_records(self._columns, alerts)
        self._restore_selection()
        if snapshot.learning_until is not None:
            until = datetime.fromtimestamp(snapshot.learning_until)
            self._learning.setText(
                f"Aprendendo os processos habituais: o sinal “primeira vez” só é emitido a partir de {until:%d/%m %H:%M}."
            )
        else:
            self._learning.setText(f"{len(alerts)} processos com sinais nesta sessão.")

    def _selected(self) -> ProcessOutbound | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        return self._model.record_at(self._proxy.mapToSource(rows[0]).row())

    def _on_selection_changed(self) -> None:
        summary = self._selected()
        if summary is None:
            return
        self._selected_key = self._key(summary)
        reasons = "\n".join(f"⚠ {signal.message}" for signal in summary.signals)
        self._inspector.setText(f"{reasons}\n\n{process_details(summary.process)}")
        self._refresh_trust_button()

    def _restore_selection(self) -> None:
        if self._selected_key is None:
            return
        for row, summary in enumerate(self._model.records()):
            if self._key(summary) == self._selected_key:
                self._table.selectRow(self._proxy.mapFromSource(self._model.index(row, 0)).row())
                return

    def _refresh_trust_button(self) -> None:
        self._trust.setEnabled(self._selected_key is not None)
        self._trust.setText(UNTRUST if self._selected_key in self._trusted else TRUST)

    def _on_trust_clicked(self) -> None:
        if self._selected_key is not None:
            self.trust_toggled.emit(self._selected_key)
