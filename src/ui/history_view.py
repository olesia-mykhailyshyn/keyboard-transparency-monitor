"""History/logs view."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Signal
from PySide6.QtGui import QFont, QColor

from src.utils.formatting import format_timestamp


class HistoryView(QWidget):
    """Display detection history and logs."""

    refresh_clicked = Signal()
    clear_history_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build history view layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Title and actions
        header_layout = QHBoxLayout()

        title = QLabel("Detection History")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        header_layout.addWidget(title)

        header_layout.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_clicked.emit)
        header_layout.addWidget(refresh_btn)

        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(self.clear_history_clicked.emit)
        header_layout.addWidget(clear_btn)

        layout.addLayout(header_layout)

        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Risk Level",
            "Score",
            "First Seen",
            "Status",
            "User Action",
        ])

        header = self.history_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)

        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.history_table.setAlternatingRowColors(True)

        layout.addWidget(self.history_table)

    def populate_history(self, records: list) -> None:
        """
        Populate history table with detection records.
        
        Args:
            records: List of detection records from database
        """
        self.history_table.setRowCount(0)

        for record in records:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)

            # Process name
            name_item = QTableWidgetItem(record['process_name'])
            self.history_table.setItem(row, 0, name_item)

            # PID
            pid_item = QTableWidgetItem(str(record['pid']))
            self.history_table.setItem(row, 1, pid_item)

            # Risk level
            risk_level = record['risk_level']
            risk_item = QTableWidgetItem(risk_level)
            risk_colors = {
                'HIGH': QColor("#DC3545"),
                'MEDIUM': QColor("#FFC107"),
                'LOW': QColor("#28A745"),
            }
            risk_item.setForeground(risk_colors.get(risk_level, QColor("#6C757D")))
            self.history_table.setItem(row, 2, risk_item)

            # Score
            score_item = QTableWidgetItem(f"{record['risk_score']:.1f}")
            self.history_table.setItem(row, 3, score_item)

            # First seen
            first_seen = record['first_seen']
            first_seen_item = QTableWidgetItem(first_seen)
            self.history_table.setItem(row, 4, first_seen_item)

            # Status
            status_item = QTableWidgetItem(record['status'])
            self.history_table.setItem(row, 5, status_item)

            # User action
            user_action = record['user_action'] or "—"
            action_item = QTableWidgetItem(user_action)
            self.history_table.setItem(row, 6, action_item)

    def clear_table(self) -> None:
        """Clear the history table."""
        self.history_table.setRowCount(0)
