ACCENT_OUT = "#ff9f43"
TEXT = "#e6e9ef"
MUTED = "#8b93a7"
BORDER = "#2c3242"

SEVERITY_COLORS = {1: "#f1c40f", 2: "#ff7f3f", 3: "#ff4d4d"}

STATUS_COLORS = {
    "starting": MUTED,
    "active": "#2ecc71",
    "paused": "#f1c40f",
    "error": "#e74c3c",
}


def widget_stylesheet(opacity: float) -> str:
    alpha = round(opacity * 255)
    return f"""
    QFrame#panel {{
        background-color: rgba(20, 23, 31, {alpha});
        border: 1px solid {BORDER};
        border-radius: 12px;
    }}
    QLabel {{ color: {TEXT}; font-size: 12px; background: transparent; }}
    QLabel#title {{ font-weight: 700; letter-spacing: 2px; }}
    QLabel#section {{ color: {MUTED}; font-size: 10px; font-weight: 700; letter-spacing: 1px; }}
    QLabel#upload {{ color: {ACCENT_OUT}; font-size: 22px; font-weight: 700; }}
    QLabel#muted {{ color: {MUTED}; }}
    QLabel#hint {{ color: {MUTED}; font-size: 11px; font-style: italic; }}
    QLabel#process {{ font-weight: 600; }}
    QLabel#amount {{ color: {ACCENT_OUT}; font-size: 11px; }}
    QLabel#detail {{ color: {MUTED}; font-size: 10px; }}
    QLabel#recent {{ font-family: monospace; font-size: 11px; }}
    QFrame#separator {{ background-color: {BORDER}; }}
    QToolButton {{ color: {MUTED}; background: transparent; border: none; font-size: 14px; padding: 0 4px; }}
    QToolButton:hover {{ color: {TEXT}; }}
    QPushButton {{
        color: {TEXT}; background-color: #262c3a; border: 1px solid {BORDER};
        border-radius: 6px; padding: 4px 8px; font-size: 11px;
    }}
    QPushButton:hover {{ background-color: #323a4d; }}
    """


WINDOW_STYLESHEET = f"""
QWidget {{ background-color: #14171f; color: {TEXT}; font-size: 12px; }}
QLineEdit, QComboBox, QSpinBox {{
    background-color: #1e2330; border: 1px solid {BORDER}; border-radius: 4px; padding: 3px 6px;
}}
QTableView {{ gridline-color: {BORDER}; selection-background-color: #2f3b55; alternate-background-color: #181c26; }}
QHeaderView::section {{ background-color: #1e2330; color: {MUTED}; border: none; padding: 4px; }}
QPushButton {{ background-color: #262c3a; border: 1px solid {BORDER}; border-radius: 6px; padding: 4px 10px; }}
QPushButton:hover {{ background-color: #323a4d; }}
QCheckBox, QLabel {{ background: transparent; }}
"""
