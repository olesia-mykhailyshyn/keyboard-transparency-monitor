"""Dashboard view showing monitoring status and overview."""

from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QScrollArea, QGridLayout
)
from PySide6.QtCore import Signal
from PySide6.QtGui import QFont

from src.utils.formatting import format_timestamp


class DashboardView(QWidget):
    """Dashboard showing high-level monitoring status."""

    scan_now_clicked = Signal()
    auto_scan_toggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build dashboard layout."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(15)

        # Title
        title = QLabel("Keyboard Transparency Monitor")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        main_layout.addWidget(title)

        # Status band
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Monitoring Status: ⏹ Stopped")
        status_font = QFont()
        status_font.setPointSize(11)
        self.status_label.setFont(status_font)
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.scan_btn = QPushButton("Scan Now")
        self.scan_btn.clicked.connect(self.scan_now_clicked.emit)
        status_layout.addWidget(self.scan_btn)

        self.auto_scan_btn = QPushButton("Start Auto Scan")
        self.auto_scan_btn.setCheckable(True)
        self.auto_scan_btn.clicked.connect(self._on_auto_scan_toggled)
        status_layout.addWidget(self.auto_scan_btn)

        main_layout.addLayout(status_layout)

        # Info cards
        cards_layout = QGridLayout()
        cards_layout.setSpacing(10)

        self.processes_card = self._create_info_card("Total Processes", "0", cards_layout, 0, 0)
        self.high_risk_card = self._create_info_card("High Risk", "0", cards_layout, 0, 1)
        self.medium_risk_card = self._create_info_card("Medium Risk", "0", cards_layout, 0, 2)
        self.low_risk_card = self._create_info_card("Low Risk", "0", cards_layout, 1, 0)
        self.last_scan_card = self._create_info_card("Last Scan", "Never", cards_layout, 1, 1)
        self.scan_interval_card = self._create_info_card("Scan Interval", "10s", cards_layout, 1, 2)

        main_layout.addLayout(cards_layout)

        # Info box
        info_group = QGroupBox("About This Tool")
        info_layout = QVBoxLayout()

        info_text = QLabel(
            "This is a heuristic-based transparency monitor designed to detect potentially "
            "suspicious process behavior related to keyboard input access.\n\n"
            "<b>Important:</b> This tool does NOT capture actual keystroke content. "
            "Detection is based on process metadata, behavior patterns, and observable signals only.\n\n"
            "Use this tool to identify unknown background processes that may warrant investigation."
        )
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)

        info_group.setLayout(info_layout)
        main_layout.addWidget(info_group)

        main_layout.addStretch()
        self.setLayout(main_layout)

    def _create_info_card(
        self, title: str, value: str, layout: QGridLayout, row: int, col: int
    ) -> QLabel:
        """Create an info card widget."""
        card_group = QGroupBox()
        card_layout = QVBoxLayout()

        title_label = QLabel(title)
        title_font = QFont()
        title_font.setPointSize(9)
        title_font.setBold(True)
        title_label.setFont(title_font)
        card_layout.addWidget(title_label)

        value_label = QLabel(value)
        value_font = QFont()
        value_font.setPointSize(14)
        value_font.setBold(True)
        value_label.setFont(value_font)
        card_layout.addWidget(value_label)

        card_group.setLayout(card_layout)
        layout.addWidget(card_group, row, col)

        return value_label

    def set_monitoring_status(self, is_running: bool) -> None:
        """Update monitoring status."""
        status_text = "⏵ Running" if is_running else "⏹ Stopped"
        self.status_label.setText(f"Monitoring Status: {status_text}")
        self.auto_scan_btn.setText("Stop Auto Scan" if is_running else "Start Auto Scan")
        self.auto_scan_btn.setChecked(is_running)

    def set_process_counts(self, total: int, high: int, medium: int, low: int) -> None:
        """Update process count displays."""
        self.processes_card.setText(str(total))
        self.high_risk_card.setText(str(high))
        self.medium_risk_card.setText(str(medium))
        self.low_risk_card.setText(str(low))

    def set_last_scan_time(self, dt: datetime) -> None:
        """Update last scan time."""
        self.last_scan_card.setText(format_timestamp(dt))

    def set_scan_interval(self, interval: float) -> None:
        """Update scan interval display."""
        self.scan_interval_card.setText(f"{interval:.1f}s")

    def _on_auto_scan_toggled(self, checked: bool) -> None:
        """Handle auto-scan toggle."""
        self.auto_scan_toggled.emit(checked)
