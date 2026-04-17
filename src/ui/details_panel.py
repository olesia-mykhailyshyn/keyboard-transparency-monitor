"""Details panel for selected process."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QHBoxLayout, QGroupBox
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QFont, QTextCursor

from src.core.models import RiskAnalysis, RiskLevel
from src.utils.formatting import format_timestamp, get_risk_color


class DetailsPanel(QWidget):
    """Display detailed information about selected process."""

    trust_process_clicked = Signal(str)  # process_name
    ignore_process_clicked = Signal(str)  # process_name
    terminate_process_clicked = Signal(int)  # pid

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_analysis: RiskAnalysis = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the details panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Title
        title = QLabel("Process Details")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Process name
        self.name_label = QLabel()
        layout.addWidget(self.name_label)

        # Risk level box
        self.risk_group = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout()

        self.risk_label = QLabel()
        risk_font = QFont()
        risk_font.setPointSize(11)
        risk_font.setBold(True)
        self.risk_label.setFont(risk_font)
        risk_layout.addWidget(self.risk_label)

        self.score_label = QLabel()
        risk_layout.addWidget(self.score_label)

        self.risk_group.setLayout(risk_layout)
        layout.addWidget(self.risk_group)

        # Reasons/Signals
        self.reasons_group = QGroupBox("Detection Reasons")
        reasons_layout = QVBoxLayout()

        self.reasons_text = QTextEdit()
        self.reasons_text.setReadOnly(True)
        self.reasons_text.setMaximumHeight(150)
        reasons_layout.addWidget(self.reasons_text)

        self.reasons_group.setLayout(reasons_layout)
        layout.addWidget(self.reasons_group)

        # Recommended action
        self.action_group = QGroupBox("Recommended Action")
        action_layout = QVBoxLayout()

        self.action_text = QTextEdit()
        self.action_text.setReadOnly(True)
        self.action_text.setMaximumHeight(100)
        action_layout.addWidget(self.action_text)

        self.action_group.setLayout(action_layout)
        layout.addWidget(self.action_group)

        # Buttons
        button_layout = QHBoxLayout()

        self.trust_btn = QPushButton("Mark as Trusted")
        self.trust_btn.clicked.connect(self._on_trust_clicked)
        button_layout.addWidget(self.trust_btn)

        self.ignore_btn = QPushButton("Ignore")
        self.ignore_btn.clicked.connect(self._on_ignore_clicked)
        button_layout.addWidget(self.ignore_btn)

        self.terminate_btn = QPushButton("Terminate Process")
        self.terminate_btn.setObjectName("dangerButton")
        self.terminate_btn.clicked.connect(self._on_terminate_clicked)
        button_layout.addWidget(self.terminate_btn)

        layout.addLayout(button_layout)
        layout.addStretch()

        self.setLayout(layout)
        self._clear_panel()

    def show_process(self, analysis: RiskAnalysis, executable: str) -> None:
        """
        Display details for a process.
        
        Args:
            analysis: RiskAnalysis object
            executable: Path to executable
        """
        self._current_analysis = analysis

        # Name with PID
        self.name_label.setText(f"<b>{analysis.process_name}</b> (PID: {analysis.pid})")

        # Risk level
        color = get_risk_color(analysis.risk_level)
        risk_text = f"Risk: <span style='color: {color}; font-weight: bold;'>{analysis.risk_level.value}</span>"
        self.risk_label.setText(risk_text)

        # Score
        self.score_label.setText(f"Risk Score: {analysis.risk_score:.1f} / 100.0")

        # Reasons
        reasons_text = "\n".join([f"• {r}" for r in analysis.reasons])
        self.reasons_text.setText(reasons_text)

        # Recommended action (in a box)
        self.action_text.setText(analysis.recommended_action)

        # Enable/disable buttons based on risk level
        self.trust_btn.setEnabled(True)
        self.ignore_btn.setEnabled(True)
        self.terminate_btn.setEnabled(analysis.risk_level == RiskLevel.HIGH)

    def _clear_panel(self) -> None:
        """Clear the panel."""
        self._current_analysis = None
        self.name_label.setText("No process selected")
        self.risk_label.setText("")
        self.score_label.setText("")
        self.reasons_text.clear()
        self.action_text.clear()
        self.trust_btn.setEnabled(False)
        self.ignore_btn.setEnabled(False)
        self.terminate_btn.setEnabled(False)

    def clear(self) -> None:
        """Clear displayed information."""
        self._clear_panel()

    def _on_trust_clicked(self) -> None:
        """Handle trust button."""
        if self._current_analysis:
            self.trust_process_clicked.emit(self._current_analysis.process_name)
            self._clear_panel()

    def _on_ignore_clicked(self) -> None:
        """Handle ignore button."""
        if self._current_analysis:
            self.ignore_process_clicked.emit(self._current_analysis.process_name)
            self._clear_panel()

    def _on_terminate_clicked(self) -> None:
        """Handle terminate button."""
        if self._current_analysis:
            self.terminate_process_clicked.emit(self._current_analysis.pid)
