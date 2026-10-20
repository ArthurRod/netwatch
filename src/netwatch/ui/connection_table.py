from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt

from netwatch.models.connection import Connection, Protocol
from netwatch.ui.formatting import (
    UNKNOWN,
    connection_process_label,
    format_bytes,
    format_remote_name,
    remote_name_note,
)

COLUMNS = (
    "Horário",
    "Processo",
    "PID",
    "Destino",
    "Domínio",
    "Porta",
    "Protocolo",
    "Enviado",
    "Recebido",
    "Estado",
)

SORT_ROLE = Qt.ItemDataRole.UserRole + 1


def _display(connection: Connection, column: int) -> str:
    remote = connection.remote
    match column:
        case 0:
            return connection.first_seen.strftime("%H:%M:%S") if connection.first_seen else UNKNOWN
        case 1:
            return connection_process_label(connection)
        case 2:
            return str(connection.pid) if connection.pid is not None else UNKNOWN
        case 3:
            return remote.ip if remote else UNKNOWN
        case 4:
            return format_remote_name(connection.remote_name)
        case 5:
            return str(remote.port) if remote else UNKNOWN
        case 6:
            return connection.protocol.value
        case 7:
            return format_bytes(connection.bytes_sent)
        case 8:
            return format_bytes(connection.bytes_received)
        case 9:
            return connection.status or UNKNOWN
    return ""


def _sort_key(connection: Connection, column: int) -> Any:
    match column:
        case 0:
            return connection.first_seen.timestamp() if connection.first_seen else -1
        case 2:
            return connection.pid if connection.pid is not None else -1
        case 5:
            return connection.remote.port if connection.remote else -1
        case 7:
            return connection.bytes_sent if connection.bytes_sent is not None else -1
        case 8:
            return connection.bytes_received if connection.bytes_received is not None else -1
    return _display(connection, column).lower()


def _tooltip(connection: Connection, column: int) -> str | None:
    if column == 4:
        return remote_name_note(connection.remote_name) or "Sem nome reverso (ainda consultando, ou o IP não tem PTR)"
    if column in (7, 8):
        if connection.protocol is Protocol.UDP:
            return "Não medido para UDP"
        return "Desde a abertura da conexão (tcp_info via ss); enviado = bytes confirmados pelo destino"
    return None


class ConnectionTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._rows: list[Connection] = []

    def set_connections(self, connections: list[Connection]) -> None:
        self.beginResetModel()
        self._rows = connections
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        connection = self._rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return _display(connection, index.column())
        if role == SORT_ROLE:
            return _sort_key(connection, index.column())
        if role == Qt.ItemDataRole.ToolTipRole:
            return _tooltip(connection, index.column())
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def connection_at(self, row: int) -> Connection:
        return self._rows[row]

    def row_of(self, key: tuple) -> int | None:
        for row, connection in enumerate(self._rows):
            if connection.key == key:
                return row
        return None


class ConnectionFilterProxy(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.setSortRole(SORT_ROLE)
        self._search = ""
        self._protocol: Protocol | None = None
        self._process: str | None = None
        self._outbound_only = True

    def set_search(self, text: str) -> None:
        self.beginFilterChange()
        self._search = text.strip().lower()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_protocol(self, protocol: Protocol | None) -> None:
        self.beginFilterChange()
        self._protocol = protocol
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_process(self, process: str | None) -> None:
        self.beginFilterChange()
        self._process = process
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_outbound_only(self, enabled: bool) -> None:
        self.beginFilterChange()
        self._outbound_only = enabled
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        connection = self.sourceModel().connection_at(source_row)
        if self._outbound_only and not connection.is_outbound:
            return False
        if self._protocol is not None and connection.protocol != self._protocol:
            return False
        if self._process is not None and connection_process_label(connection) != self._process:
            return False
        if not self._search:
            return True
        haystack = " ".join(
            (
                connection_process_label(connection),
                connection.remote.ip if connection.remote else "",
                connection.remote_name.name if connection.remote_name else "",
                str(connection.pid or ""),
                connection.process.command if connection.process else "",
                (connection.process.exe or "") if connection.process else "",
            )
        ).lower()
        return self._search in haystack
