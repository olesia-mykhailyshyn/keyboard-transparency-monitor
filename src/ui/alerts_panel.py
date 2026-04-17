"""Alerts and notifications panel."""

from datetime import datetime
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QScrollArea, QGroupBox
from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont

from src.core.models import RiskAnalysis, RiskLevel
from src.utils.formatting import format_timestamp, get_risk_color


class AlertsPanel(QWidget):
    """Display recent alerts and notifications."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._alerts = []

    def _setup_ui(self) -> None:
        """Build alerts panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Title
        title = QLabel("Recent Alerts")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Scrollable alerts area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        self.alerts_container = QWidget()
        self.alerts_layout = QVBoxLayout(self.alerts_container)
        self.alerts_layout.setContentsMargins(0, 0, 0, 0)
        self.alerts_layout.setSpacing(8)

        scroll.setWidget(self.alerts_container)
        layout.addWidget(scroll)

    def add_alert(self, analysis: RiskAnalysis) -> None:
        """Add a detection alert."""
        alert = QGroupBox(f"{analysis.process_name} (PID: {analysis.pid})")
        alert.setStyleSheet(f"border-left: 4px solid {get_risk_color(analysis.risk_level)};")

        alert_layout = QVBoxLayout()

        # Risk level
        risk_label = QLabel(f"<b>Risk Level:</b> {analysis.risk_level.value} ({analysis.risk_score:.1f})")
        risk_label.setStyleSheet(f"color: {get_risk_color(analysis.risk_level)};")
        alert_layout.addWidget(risk_label)

        # Top reason
        if analysis.reasons:
            reason_label = QLabel(f"<b>Reason:</b> {analysis.reasons[0][:100]}")
            reason_label.setWordWrap(True)
            alert_layout.addWidget(reason_label)

        # Timestamp
        time_label = QLabel(f"<i>Detected: {format_timestamp(analysis.timestamp)}</i>")
        time_label.setStyleSheet("color: #6c757d; font-size: 10px;")
        alert_layout.addWidget(time_label)

        alert.setLayout(alert_layout)
        self.alerts_layout.addWidget(alert)
        self._alerts.append((analysis, alert))

        # Keep only last 10 alerts
        if len(self._alerts) > 10:
            old_analysis, old_alert = self._alerts.pop(0)
            self.alerts_layout.removeWidget(old_alert)
            old_alert.deleteLater()

    def clear_alerts(self) -> None:
        """Clear all alerts."""
        for _, alert in self._alerts:
            self.alerts_layout.removeWidget(alert)
            alert.deleteLater()
        self._alerts.clear()
