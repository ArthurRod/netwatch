from dataclasses import replace

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QSlider,
    QSpinBox,
)

from netwatch.config import (
    MAX_INTERVAL_MS,
    MAX_RETENTION_DAYS,
    MIN_INTERVAL_MS,
    MIN_OPACITY,
    MIN_RETENTION_DAYS,
    Settings,
)
from netwatch.ui.theme import WINDOW_STYLESHEET


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, platform_name: str, autostart: bool) -> None:
        super().__init__()
        self.setWindowTitle("NetWatch — Configurações")
        self.setStyleSheet(WINDOW_STYLESHEET)
        self._settings = settings

        self._opacity = QSlider(Qt.Orientation.Horizontal)
        self._opacity.setRange(round(MIN_OPACITY * 100), 100)
        self._opacity.setValue(round(settings.opacity * 100))

        self._interval = QSpinBox()
        self._interval.setRange(MIN_INTERVAL_MS, MAX_INTERVAL_MS)
        self._interval.setSingleStep(250)
        self._interval.setSuffix(" ms")
        self._interval.setValue(settings.interval_ms)

        self._always_on_top = QCheckBox("Manter sobre outras janelas")
        self._always_on_top.setChecked(settings.always_on_top)

        self._prefer_xwayland = QCheckBox("Usar XWayland no Wayland (requer reiniciar)")
        self._prefer_xwayland.setChecked(settings.prefer_xwayland)

        self._history_enabled = QCheckBox("Gravar histórico de conexões de saída")
        self._history_enabled.setChecked(settings.history_enabled)
        self._retention = QSpinBox()
        self._retention.setRange(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
        self._retention.setSuffix(" dias")
        self._retention.setValue(settings.history_retention_days)
        self._retention.setEnabled(settings.history_enabled)
        self._history_enabled.toggled.connect(self._retention.setEnabled)

        self._autostart = QCheckBox("Iniciar automaticamente ao entrar no Ubuntu")
        self._autostart.setChecked(autostart)

        self._resolve_names = QCheckBox("Resolver nomes dos destinos (DNS reverso)")
        self._resolve_names.setChecked(settings.resolve_names)
        self._resolve_names.setToolTip(
            "Consulta o nome de cada IP novo no seu servidor DNS (com cache). "
            "O nome reverso é escolhido pelo dono do IP e pode não ser o site acessado."
        )

        platform_note = QLabel(f"Plataforma gráfica atual: {platform_name}")
        platform_note.setObjectName("muted")
        if platform_name == "wayland":
            platform_note.setText(
                f"{platform_note.text()} — o GNOME ignora “sempre visível” e a posição salva neste modo."
            )
        platform_note.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        form = QFormLayout(self)
        form.addRow("Opacidade", self._opacity)
        form.addRow("Intervalo de coleta", self._interval)
        form.addRow(self._autostart)
        form.addRow(self._always_on_top)
        form.addRow(self._prefer_xwayland)
        form.addRow(self._history_enabled)
        form.addRow("Manter histórico por", self._retention)
        form.addRow(self._resolve_names)
        form.addRow(platform_note)
        form.addRow(buttons)

    def autostart_enabled(self) -> bool:
        return self._autostart.isChecked()

    def result_settings(self) -> Settings:
        return replace(
            self._settings,
            opacity=self._opacity.value() / 100,
            interval_ms=self._interval.value(),
            always_on_top=self._always_on_top.isChecked(),
            prefer_xwayland=self._prefer_xwayland.isChecked(),
            history_enabled=self._history_enabled.isChecked(),
            history_retention_days=self._retention.value(),
            resolve_names=self._resolve_names.isChecked(),
        ).normalized()
