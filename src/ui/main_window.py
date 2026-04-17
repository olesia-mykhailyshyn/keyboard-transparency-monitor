"""Main application window."""

import psutil
from pathlib import Path
from datetime import datetime
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QMessageBox, QInputDialog, QSplitter
)
from PySide6.QtCore import Qt, QThread, Signal, QObject
from PySide6.QtGui import QFont

from src.core.process_scanner import ProcessScanner
from src.core.risk_engine import RiskEngine
from src.core.monitor_service import MonitorService
from src.core.trusted_registry import TrustedRegistry
from src.core.event_logger import EventLogger
from src.core.models import RiskAnalysis
from src.ui.styles import MAIN_STYLESHEET
from src.ui.dashboard_view import DashboardView
from src.ui.process_table import ProcessTable
from src.ui.details_panel import DetailsPanel
from src.ui.alerts_panel import AlertsPanel
from src.ui.history_view import HistoryView
from src.ui.settings_view import SettingsView


class MonitorWorker(QObject):
    """Worker for background monitoring operations."""

    detection_signal = Signal(list)  # List[RiskAnalysis]
    status_signal = Signal(str)

    def __init__(self, monitor_service: MonitorService):
        super().__init__()
        self.monitor_service = monitor_service
        self.monitor_service.add_detection_callback(self._on_detections)

    def _on_detections(self, analyses: list) -> None:
        """Callback from monitor service."""
        self.detection_signal.emit(analyses)


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Keyboard Transparency Monitor")
        self.setGeometry(100, 100, 1400, 900)

        # Initialize core components
        self.storage_dir = Path.home() / '.ktm'
        self.storage_dir.mkdir(exist_ok=True)

        self.scanner = ProcessScanner()
        self.risk_engine = RiskEngine()
        self.event_logger = EventLogger(self.storage_dir)
        self.trusted_registry = TrustedRegistry(self.storage_dir)
        self.monitor_service = MonitorService(self.scanner, self.risk_engine)

        # Update risk engine with trusted processes
        self._sync_trusted_processes()

        # Worker thread
        self.worker = MonitorWorker(self.monitor_service)
        self.worker.detection_signal.connect(self._on_detections)

        # State
        self.last_scan_time: Optional[datetime] = None
        self._detection_cache = {}  # pid -> (analysis, process_info)

        # UI
        self._setup_ui()
        self.setStyleSheet(MAIN_STYLESHEET)

    def _setup_ui(self) -> None:
        """Build main window layout."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Tab widget
        self.tabs = QTabWidget()

        # Dashboard tab
        self.dashboard = DashboardView()
        self.dashboard.scan_now_clicked.connect(self._on_scan_now)
        self.dashboard.auto_scan_toggled.connect(self._on_auto_scan_toggled)
        self.tabs.addTab(self.dashboard, "Dashboard")

        # Main monitoring tab (processes + details)
        monitor_widget = QWidget()
        monitor_layout = QHBoxLayout(monitor_widget)
        monitor_layout.setContentsMargins(10, 10, 10, 10)
        monitor_layout.setSpacing(10)

        # Left side: table + alerts
        left_layout = QVBoxLayout()

        # Table
        table_label = QFont()
        table_label.setBold(True)
        self.process_table = ProcessTable()
        self.process_table.process_selected.connect(self._on_process_selected)
        left_layout.addWidget(self.process_table)

        # Alerts
        self.alerts_panel = AlertsPanel()
        left_layout.addWidget(self.alerts_panel)

        # Splitter for left side
        monitor_layout.addLayout(left_layout, 2)

        # Right side: details
        self.details_panel = DetailsPanel()
        self.details_panel.trust_process_clicked.connect(self._on_trust_process)
        self.details_panel.ignore_process_clicked.connect(self._on_ignore_process)
        self.details_panel.terminate_process_clicked.connect(self._on_terminate_process)
        monitor_layout.addWidget(self.details_panel, 1)

        self.tabs.addTab(monitor_widget, "Monitor")

        # History tab
        self.history_view = HistoryView()
        self.history_view.refresh_clicked.connect(self._on_refresh_history)
        self.history_view.clear_history_clicked.connect(self._on_clear_history)
        self.tabs.addTab(self.history_view, "History")

        # Settings tab
        self.settings_view = SettingsView()
        self.settings_view.scan_interval_changed.connect(self._on_scan_interval_changed)
        self.settings_view.add_trusted_process.connect(self._on_add_trusted_process)
        self.settings_view.remove_trusted_process.connect(self._on_remove_trusted_process)
        self.tabs.addTab(self.settings_view, "Settings")

        main_layout.addWidget(self.tabs)
        central_widget.setLayout(main_layout)

        # Initialize settings display
        self.settings_view.set_trusted_processes(self.trusted_registry.get_all())

    def _sync_trusted_processes(self) -> None:
        """Sync trusted processes to risk engine."""
        self.risk_engine.trusted_processes = self.trusted_registry.get_all()

    def _on_scan_now(self) -> None:
        """Handle manual scan."""
        try:
            analyses = self.monitor_service.scan_now()
            self.last_scan_time = datetime.now()
            self._on_detections(analyses)
            self.dashboard.set_last_scan_time(self.last_scan_time)
        except Exception as e:
            QMessageBox.critical(self, "Scan Error", f"Error during scan: {e}")

    def _on_auto_scan_toggled(self, checked: bool) -> None:
        """Handle auto-scan toggle."""
        if checked:
            self.monitor_service.start()
            self.dashboard.set_monitoring_status(True)
        else:
            self.monitor_service.stop()
            self.dashboard.set_monitoring_status(False)

    def _on_scan_interval_changed(self, interval: float) -> None:
        """Handle scan interval change."""
        self.monitor_service.set_scan_interval(interval)
        self.dashboard.set_scan_interval(interval)

    def _on_detections(self, analyses: list) -> None:
        """Handle detection updates from monitor service."""
        self.last_scan_time = datetime.now()

        # Count by risk level
        high = sum(1 for a in analyses if a.risk_level.value == 'HIGH')
        medium = sum(1 for a in analyses if a.risk_level.value == 'MEDIUM')
        low = sum(1 for a in analyses if a.risk_level.value == 'LOW')
        total = self.scanner.last_scan_time  # Use for reference

        # Update dashboard
        total_procs = len(self.scanner.scan_all_processes())
        self.dashboard.set_process_counts(total_procs, high, medium, low)
        self.dashboard.set_last_scan_time(self.last_scan_time)

        # Update table
        self.process_table.clear_all()
        for analysis in analyses:
            # Get process info for memory/threads
            proc_info = self.scanner.get_process_by_pid(analysis.pid)
            if proc_info:
                self.process_table.add_or_update_process(
                    analysis,
                    proc_info.memory_mb,
                    proc_info.num_threads
                )

                # Log detection
                self.event_logger.log_detection(analysis, proc_info.executable)

            # Add to alerts
            self.alerts_panel.add_alert(analysis)

    def _on_process_selected(self, analysis: RiskAnalysis) -> None:
        """Handle process selection in table."""
        proc_info = self.scanner.get_process_by_pid(analysis.pid)
        if proc_info:
            self.details_panel.show_process(analysis, proc_info.executable)

    def _on_trust_process(self, process_name: str) -> None:
        """Mark process as trusted."""
        self.trusted_registry.add(process_name)
        self._sync_trusted_processes()
        self.settings_view.set_trusted_processes(self.trusted_registry.get_all())
        QMessageBox.information(self, "Success", f"Process '{process_name}' marked as trusted.")
        self._on_scan_now()

    def _on_ignore_process(self, process_name: str) -> None:
        """Ignore process alert."""
        QMessageBox.information(self, "Ignored", f"Ignoring alerts for '{process_name}'.")
        self._on_scan_now()

    def _on_terminate_process(self, pid: int) -> None:
        """Terminate a process."""
        reply = QMessageBox.warning(
            self,
            "Confirm Termination",
            f"Terminate process {pid}?\n\nThis action cannot be undone.",
            QMessageBox.Ok | QMessageBox.Cancel
        )
        if reply == QMessageBox.Ok:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                QMessageBox.information(self, "Success", f"Process {pid} terminated.")
                self._on_scan_now()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not terminate process: {e}")

    def _on_add_trusted_process(self) -> None:
        """Add a trusted process via dialog."""
        text, ok = QInputDialog.getText(
            self,
            "Add Trusted Process",
            "Enter process name (e.g., explorer.exe):"
        )
        if ok and text:
            self.trusted_registry.add(text.strip())
            self._sync_trusted_processes()
            self.settings_view.set_trusted_processes(self.trusted_registry.get_all())

    def _on_remove_trusted_process(self, process_name: str) -> None:
        """Remove a trusted process."""
        self.trusted_registry.remove(process_name)
        self._sync_trusted_processes()
        self.settings_view.set_trusted_processes(self.trusted_registry.get_all())

    def _on_refresh_history(self) -> None:
        """Refresh history view."""
        records = self.event_logger.get_recent_detections(limit=100)
        self.history_view.populate_history(records)

    def _on_clear_history(self) -> None:
        """Clear detection history."""
        reply = QMessageBox.warning(
            self,
            "Clear History",
            "Clear all detection history? This cannot be undone.",
            QMessageBox.Ok | QMessageBox.Cancel
        )
        if reply == QMessageBox.Ok:
            # For MVP, just clear the view
            self.history_view.clear_table()

    def closeEvent(self, event) -> None:
        """Handle window close."""
        self.monitor_service.stop()
        event.accept()
