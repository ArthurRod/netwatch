import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget


class PlainLabel(QLabel):
    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setText(text)


def plain_tooltip(text: str) -> str:
    if not text:
        return ""
    return f"<p style='white-space:pre-wrap'>{html.escape(text)}</p>"
