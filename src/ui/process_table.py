"""Process table widget for displaying detected processes."""

from datetime import datetime
from typing import Optional

from PySide6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from src.core.models import RiskLevel, RiskAnalysis
from src.utils.formatting import format_time_ago, format_memory_mb


class ProcessTable(QTableWidget):
    """Table showing detected processes with risk information."""

    process_selected = Signal(RiskAnalysis)
    context_menu_requested = Signal(RiskAnalysis, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_table()
        self._current_data: dict = {}  # pid -> RiskAnalysis

    def _setup_table(self) -> None:
        """Configure table columns and appearance."""
        columns = [
            "Process Name",
            "PID",
            "Risk Level",
            "Score",
            "Memory",
            "Threads",
            "First Seen",
        ]
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)

        # Set sizing
        header = self.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Process name
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # PID
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Risk
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Score
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Memory
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Threads
        header.setSectionResizeMode(6, QHeaderView.Stretch)  # First Seen

        # Selection and interaction
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.itemSelectionChanged.connect(self._on_selection_changed)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

    def add_or_update_process(self, analysis: RiskAnalysis, memory_mb: float, num_threads: int) -> None:
        """
        Add or update a process row.
        
        Args:
            analysis: RiskAnalysis for the process
            memory_mb: Memory usage in MB
            num_threads: Thread count
        """
        pid = analysis.pid

        # Check if row exists
        row = None
        for i in range(self.rowCount()):
            item = self.item(i, 1)  # PID column
            if item and int(item.text()) == pid:
                row = i
                break

        # Create new row if needed
        if row is None:
            row = self.rowCount()
            self.insertRow(row)

        # Update row data
        self._current_data[pid] = analysis

        # Process name
        name_item = QTableWidgetItem(analysis.process_name)
        self._apply_risk_color(name_item, analysis.risk_level)
        self.setItem(row, 0, name_item)

        # PID
        pid_item = QTableWidgetItem(str(pid))
        self.setItem(row, 1, pid_item)

        # Risk level
        risk_item = QTableWidgetItem(analysis.risk_level.value)
        self._apply_risk_color(risk_item, analysis.risk_level)
        risk_font = QFont()
        risk_font.setBold(True)
        risk_item.setFont(risk_font)
        self.setItem(row, 2, risk_item)

        # Risk score
        score_item = QTableWidgetItem(f"{analysis.risk_score:.1f}")
        self.setItem(row, 3, score_item)

        # Memory
        memory_item = QTableWidgetItem(format_memory_mb(memory_mb))
        self.setItem(row, 4, memory_item)

        # Threads
        threads_item = QTableWidgetItem(str(num_threads))
        self.setItem(row, 5, threads_item)

        # First seen
        first_seen_item = QTableWidgetItem(format_time_ago(analysis.timestamp))
        self.setItem(row, 6, first_seen_item)

    def clear_all(self) -> None:
        """Clear all rows from table."""
        self.setRowCount(0)
        self._current_data.clear()

    def _apply_risk_color(self, item: QTableWidgetItem, risk_level: RiskLevel) -> None:
        """Apply color to item based on risk level."""
        colors = {
            RiskLevel.LOW: QColor("#28A745"),
            RiskLevel.MEDIUM: QColor("#FFC107"),
            RiskLevel.HIGH: QColor("#DC3545"),
        }
        color = colors.get(risk_level, QColor("#6C757D"))
        item.setForeground(color)

    def _on_selection_changed(self) -> None:
        """Handle row selection."""
        selected = self.selectedIndexes()
        if selected:
            pid = int(self.item(selected[0].row(), 1).text())
            if pid in self._current_data:
                self.process_selected.emit(self._current_data[pid])

    def _on_context_menu(self, pos) -> None:
        """Handle right-click context menu."""
        item = self.itemAt(pos)
        if not item:
            return

        pid = int(self.item(item.row(), 1).text())
        if pid not in self._current_data:
            return

        analysis = self._current_data[pid]
        self.context_menu_requested.emit(analysis, pos)

    def get_selected_process(self) -> Optional[RiskAnalysis]:
        """Get currently selected process analysis."""
        selected = self.selectedIndexes()
        if selected:
            pid = int(self.item(selected[0].row(), 1).text())
            return self._current_data.get(pid)
        return None
