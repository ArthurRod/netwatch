from collections import deque

from PySide6.QtCore import QPoint, QPointF, Qt, Signal
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLayout,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from netwatch.models.connection import ProcessOutbound, Snapshot
from netwatch.monitoring.signals import untrusted_alerts
from netwatch.ui.formatting import (
    UNKNOWN,
    connection_label,
    format_bytes,
    format_rate,
    destination_line,
    process_details,
    process_label,
    short_destination,
    service_hint,
)
from netwatch.ui.plain import PlainLabel, plain_tooltip
from netwatch.ui.theme import ACCENT_OUT, SEVERITY_COLORS, STATUS_COLORS, widget_stylesheet

TOP_PROCESSES = 4
RECENT_ROWS = 3
SPARKLINE_POINTS = 60


class Sparkline(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._values: deque[float] = deque(maxlen=SPARKLINE_POINTS)
        self.setFixedHeight(28)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def push(self, value: float | None) -> None:
        self._values.append(value or 0.0)
        self.update()

    def paintEvent(self, event) -> None:
        if len(self._values) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width, height = self.width(), self.height() - 2
        peak = max(self._values) or 1.0
        step = width / (SPARKLINE_POINTS - 1)
        offset = (SPARKLINE_POINTS - len(self._values)) * step

        points = [
            QPointF(offset + index * step, 1 + height - (value / peak) * height)
            for index, value in enumerate(self._values)
        ]
        line = QPainterPath(points[0])
        for point in points[1:]:
            line.lineTo(point)

        area = QPainterPath(line)
        area.lineTo(points[-1].x(), height + 1)
        area.lineTo(points[0].x(), height + 1)
        area.closeSubpath()

        fill = QColor(ACCENT_OUT)
        fill.setAlpha(50)
        painter.fillPath(area, fill)
        painter.setPen(QPen(QColor(ACCENT_OUT), 1.5))
        painter.drawPath(line)


class FloatingWidget(QWidget):
    details_requested = Signal()
    alerts_requested = Signal()
    pause_toggled = Signal()
    settings_requested = Signal()
    hide_requested = Signal()
    quit_requested = Signal()
    position_changed = Signal(QPoint)

    def __init__(self, opacity: float, always_on_top: bool) -> None:
        super().__init__()
        self.setWindowTitle("NetWatch")
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._apply_flags(always_on_top)
        self.setFixedWidth(320)
        self._drag_origin: QPoint | None = None
        self._trusted: set[str] = set()

        self._panel = QFrame(self)
        self._panel.setObjectName("panel")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)
        outer.addWidget(self._panel)

        layout = QVBoxLayout(self._panel)
        layout.setContentsMargins(14, 10, 14, 12)
        layout.setSpacing(6)
        layout.addLayout(self._build_header())
        layout.addWidget(self._section_title("SAINDO DO PC"))
        layout.addLayout(self._build_outbound())
        layout.addWidget(self._separator())
        layout.addWidget(self._section_title("PARA ONDE ESTÁ INDO"))
        layout.addLayout(self._build_destinations())
        layout.addWidget(self._separator())
        layout.addWidget(self._section_title("NOVAS CONEXÕES"))
        layout.addLayout(self._build_recent())
        layout.addSpacing(4)
        layout.addLayout(self._build_footer())

        self.set_opacity(opacity)
        self.set_status("starting")

    def _apply_flags(self, always_on_top: bool) -> None:
        flags = Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool
        if always_on_top:
            flags |= Qt.WindowType.WindowStaysOnTopHint
        self.setWindowFlags(flags)

    def set_always_on_top(self, enabled: bool) -> None:
        visible = self.isVisible()
        self._apply_flags(enabled)
        if visible:
            self.show()

    def set_opacity(self, opacity: float) -> None:
        self.setStyleSheet(widget_stylesheet(opacity))

    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        title = PlainLabel("NETWATCH")
        title.setObjectName("title")
        self._status_dot = PlainLabel("●")
        self._status_text = PlainLabel()
        self._status_text.setObjectName("muted")
        self._helper = PlainLabel("eBPF")
        self._helper.setObjectName("helper")
        self._helper.setVisible(False)
        self._alerts = QToolButton()
        self._alerts.setObjectName("alerts")
        self._alerts.setToolTip("Processos com sinais de suspeita")
        self._alerts.clicked.connect(self.alerts_requested)
        self._alerts.setVisible(False)
        minimize = QToolButton(text="─")
        minimize.setToolTip("Esconder na bandeja")
        minimize.clicked.connect(self.hide_requested)
        close = QToolButton(text="×")
        close.setToolTip("Encerrar o NetWatch")
        close.clicked.connect(self.quit_requested)
        header.addWidget(title)
        header.addSpacing(6)
        header.addWidget(self._status_dot)
        header.addWidget(self._status_text)
        header.addStretch(1)
        header.addWidget(self._helper)
        header.addWidget(self._alerts)
        header.addWidget(minimize)
        header.addWidget(close)
        return header

    def _build_outbound(self) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(2)
        rates = QHBoxLayout()
        self._upload = PlainLabel(f"↑ {UNKNOWN}")
        self._upload.setObjectName("upload")
        self._download = PlainLabel(f"↓ {UNKNOWN}")
        self._download.setObjectName("muted")
        self._download.setToolTip("Entrada, para contexto")
        rates.addWidget(self._upload)
        rates.addStretch(1)
        rates.addWidget(self._download, alignment=Qt.AlignmentFlag.AlignBottom)
        box.addLayout(rates)

        self._sparkline = Sparkline()
        box.addWidget(self._sparkline)

        totals = QGridLayout()
        totals.setHorizontalSpacing(8)
        totals.setVerticalSpacing(2)
        self._session_sent = PlainLabel(UNKNOWN)
        self._outbound_count = PlainLabel(UNKNOWN)
        totals.addWidget(self._muted("Enviado na sessão"), 0, 0)
        totals.addWidget(self._session_sent, 0, 1, alignment=Qt.AlignmentFlag.AlignRight)
        totals.addWidget(self._muted("Conexões de saída"), 1, 0)
        totals.addWidget(self._outbound_count, 1, 1, alignment=Qt.AlignmentFlag.AlignRight)
        box.addLayout(totals)
        return box

    def _build_destinations(self) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(1)
        self._destination_rows: list[tuple[PlainLabel, PlainLabel, PlainLabel, PlainLabel]] = []
        for _ in range(TOP_PROCESSES):
            row = QHBoxLayout()
            row.setSpacing(4)
            marker = PlainLabel()
            marker.setFixedWidth(10)
            name = PlainLabel()
            name.setObjectName("process")
            amount = PlainLabel()
            amount.setObjectName("amount")
            row.addWidget(marker)
            row.addWidget(name)
            row.addStretch(1)
            row.addWidget(amount)
            detail = PlainLabel()
            detail.setObjectName("detail")
            box.addLayout(row)
            box.addWidget(detail)
            self._destination_rows.append((marker, name, amount, detail))
        self._unattributed = PlainLabel()
        self._unattributed.setObjectName("hint")
        self._unattributed.setToolTip(
            "Diferença entre o envio medido na interface e o que foi atribuído a conexões TCP:\n"
            "UDP/QUIC, containers, cabeçalhos/ACKs do TCP e, sem o helper,\n"
            "conexões que abriram e fecharam entre duas leituras."
        )
        box.addWidget(self._unattributed)
        return box

    def _build_recent(self) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(1)
        self._recent_rows = []
        for _ in range(RECENT_ROWS):
            label = PlainLabel()
            label.setObjectName("recent")
            box.addWidget(label)
            self._recent_rows.append(label)
        return box

    def _build_footer(self) -> QHBoxLayout:
        footer = QHBoxLayout()
        details = QPushButton("Detalhes")
        details.clicked.connect(self.details_requested)
        self._pause = QPushButton("Pausar")
        self._pause.clicked.connect(self.pause_toggled)
        settings = QPushButton("Config.")
        settings.clicked.connect(self.settings_requested)
        for button in (details, self._pause, settings):
            footer.addWidget(button)
        return footer

    def _section_title(self, text: str) -> PlainLabel:
        label = PlainLabel(text)
        label.setObjectName("section")
        return label

    def _muted(self, text: str) -> PlainLabel:
        label = PlainLabel(text)
        label.setObjectName("muted")
        return label

    def _separator(self) -> QFrame:
        line = QFrame()
        line.setObjectName("separator")
        line.setFixedHeight(1)
        return line

    def set_status(self, status: str) -> None:
        texts = {
            "starting": "Iniciando…",
            "active": "Monitorando",
            "paused": "Pausado",
            "error": "Falha na coleta",
        }
        self._status_dot.setStyleSheet(f"color: {STATUS_COLORS[status]};")
        self._status_text.setText(texts[status])
        self._pause.setText("Retomar" if status == "paused" else "Pausar")

    def update_snapshot(self, snapshot: Snapshot) -> None:
        traffic = snapshot.traffic
        self._upload.setText(f"↑ {format_rate(traffic.sent_per_second)}")
        self._download.setText(f"↓ {format_rate(traffic.received_per_second)}")
        self._upload.setToolTip(f"Interfaces medidas: {', '.join(traffic.interfaces) or UNKNOWN}")
        self._sparkline.push(traffic.sent_per_second)
        self._session_sent.setText(format_bytes(traffic.session_sent))
        self._outbound_count.setText(str(snapshot.outbound_count))
        self._update_destinations(snapshot)
        self._update_alerts(snapshot)
        self._update_helper(snapshot)
        self._update_recent(snapshot)

    def _update_destinations(self, snapshot: Snapshot) -> None:
        summaries = snapshot.outbound_by_process
        for index, (marker, name, amount, detail) in enumerate(self._destination_rows):
            if index >= len(summaries):
                for label in (marker, name, amount, detail):
                    label.clear()
                continue
            summary = summaries[index]
            self._set_marker(marker, summary)
            name.setText(self._process_name(summary.process_name, snapshot))
            name.setToolTip(plain_tooltip(self._process_tooltip(summary)))
            amount.setText(self._amount_text(summary))
            detail.setText(self._detail_text(summary, snapshot))
            detail.setToolTip(
                plain_tooltip("\n".join(destination_line(ip, snapshot.remote_names.get(ip)) for ip in summary.destinations))
            )
        if not summaries:
            self._destination_rows[0][1].setText("Nenhuma conexão de saída")

        rate = snapshot.unattributed_sent_per_second
        self._unattributed.setText(f"Sem atribuição ↑ {format_rate(rate)}" if rate is not None else "")
        self._unattributed.setVisible(rate is not None)

    def set_trusted(self, trusted: set[str]) -> None:
        self._trusted = trusted

    def _is_alert(self, summary: ProcessOutbound) -> bool:
        return bool(summary.signals) and summary.process is not None and summary.process.group_key not in self._trusted

    def _set_marker(self, marker: PlainLabel, summary: ProcessOutbound) -> None:
        if not self._is_alert(summary):
            marker.clear()
            return
        marker.setText("●")
        marker.setStyleSheet(f"color: {SEVERITY_COLORS[summary.severity]};")

    def _process_tooltip(self, summary: ProcessOutbound) -> str:
        details = process_details(summary.process)
        if not summary.signals:
            return details
        reasons = "\n".join(f"⚠ {signal.message}" for signal in summary.signals)
        trusted = "\n(marcado como confiável)" if not self._is_alert(summary) else ""
        return f"{reasons}{trusted}\n\n{details}"

    def _update_helper(self, snapshot: Snapshot) -> None:
        status = snapshot.helper_status
        self._helper.setVisible(snapshot.helper_connected)
        if not snapshot.helper_connected:
            return
        if not status:
            color = STATUS_COLORS["starting"]
        elif snapshot.helper_active:
            color = STATUS_COLORS["active"]
        else:
            color = STATUS_COLORS["error"]
        self._helper.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: 700;")
        self._helper.setToolTip(
            plain_tooltip(
                "Helper privilegiado conectado\n"
                f"Conexões TCP (eBPF): {status.get('tcp', '?')}\n"
                f"Consultas DNS: {status.get('dns', '?')}"
            )
        )

    def _update_alerts(self, snapshot: Snapshot) -> None:
        alerts = untrusted_alerts(snapshot.outbound_by_process, self._trusted)
        self._alerts.setVisible(bool(alerts))
        if not alerts:
            return
        worst = max(alert.severity for alert in alerts)
        self._alerts.setText(f"⚠ {len(alerts)}")
        self._alerts.setStyleSheet(f"color: {SEVERITY_COLORS[worst]}; font-weight: 700;")

    def _process_name(self, name: str | None, snapshot: Snapshot) -> str:
        if name is not None:
            return name
        services = sorted(
            {service_hint(c) for c in snapshot.connections if c.is_outbound and c.pid is None} - {None}
        )
        return f"{process_label(None)} ({', '.join(services)})" if services else process_label(None)

    def _amount_text(self, summary: ProcessOutbound) -> str:
        if summary.session_sent is None:
            return ""
        return f"↑ {format_rate(summary.sent_per_second)} · {format_bytes(summary.session_sent)}"

    def _detail_text(self, summary: ProcessOutbound, snapshot: Snapshot) -> str:
        first = summary.destinations[0] if summary.destinations else None
        destination = short_destination(first, snapshot.remote_names.get(first)) if first else UNKNOWN
        extra = len(summary.destinations) - 1
        suffix = f" +{extra}" if extra > 0 else ""
        count = f"{summary.connection_count} conn" if summary.connection_count else "sem conexão agora"
        return f"{count} · {destination}{suffix}"

    def _update_recent(self, snapshot: Snapshot) -> None:
        for index, label in enumerate(self._recent_rows):
            if index >= len(snapshot.recent_outbound):
                label.clear()
                continue
            connection = snapshot.recent_outbound[index]
            seen = connection.first_seen.strftime("%H:%M:%S") if connection.first_seen else UNKNOWN
            label.setText(f"{seen}  {connection_label(connection)}")

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return super().mousePressEvent(event)
        handle = self.windowHandle()
        if handle is not None and handle.startSystemMove():
            return
        self._drag_origin = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag_origin is not None:
            self.move(event.globalPosition().toPoint() - self._drag_origin)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_origin = None
        super().mouseReleaseEvent(event)

    def moveEvent(self, event) -> None:
        super().moveEvent(event)
        self.position_changed.emit(self.pos())
