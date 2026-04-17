"""
Cyberpunk surveillance-style main window for Keyboard Transparency Monitor.

Layout:
- Top bar: Controls and status
- Left panel: Process monitor table  
- Center panel: Scanner visualization
- Right panel: Process details
- Bottom panel: Alerts and timeline
"""

import sys
from pathlib import Path
from typing import Optional, Callable

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QScrollArea, QHeaderView,
    QComboBox, QSpinBox, QDialog
)
from PySide6.QtCore import Qt, QTimer, Signal, QSize, QObject
from PySide6.QtGui import QFont, QIcon, QColor

from .cyberpunk_styles import COLORS, MAIN_STYLESHEET, MONITOR_STYLESHEET
from .widgets.cyberpunk_widgets import (
    NeonButton, GlowFrame, RiskIndicator, ConfidenceBar,
    ScannerIndicator, ActivityWave, StatusIndicator
)


class ProcessDetectionSignals(QObject):
    """Qt signals for thread-safe process updates."""
    process_detected = Signal(object, object)  # (process, assessment)
    alert_generated = Signal(object, object, object)  # (process, assessment, alert)


class CyberpunkMainWindow(QMainWindow):
    """Main application window with cyberpunk aesthetic."""
    
    # Signals for backend integration
    process_blocked = Signal(str)  # process_name
    process_trusted = Signal(str)
    process_terminated = Signal(str)
    
    def __init__(self, app_context=None, demo_mode=False):
        super().__init__()
        
        self.app_context = app_context
        self.demo_mode = demo_mode
        self.selected_process = None
        
        # Create signals object for thread-safe updates
        self.signals = ProcessDetectionSignals()
        self.signals.process_detected.connect(self._on_process_detected_safe)
        self.signals.alert_generated.connect(self._on_alert_generated_safe)
        
        # Apply cyberpunk stylesheet
        self.setStyleSheet(MAIN_STYLESHEET)
        
        # Setup window
        self.setWindowTitle("KEYBOARD TRANSPARENCY MONITOR")
        self.setWindowIcon(QIcon())
        self.setGeometry(0, 0, 1600, 1000)
        
        # Initialize UI
        self.init_ui()
        
        # Auto-start scanning when window loads
        QTimer.singleShot(1000, self.auto_start_scan)
        
        # Setup demo data timer
        if self.demo_mode:
            self.demo_timer = QTimer()
            self.demo_timer.timeout.connect(self.update_demo_data)
            self.demo_timer.start(2000)  # Update every 2 seconds
    
    def init_ui(self):
        """Initialize the UI components."""
        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Main layout
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 1. Top bar
        top_bar = self.create_top_bar()
        main_layout.addWidget(top_bar)
        
        # 2. Main content area (left, center, right)
        content_layout = QHBoxLayout()
        content_layout.setSpacing(5)
        content_layout.setContentsMargins(5, 5, 5, 5)
        
        # Left panel - Process Monitor
        left_panel = self.create_left_panel()
        content_layout.addWidget(left_panel, 2)
        
        # Center panel - Scanner
        center_panel = self.create_center_panel()
        content_layout.addWidget(center_panel, 1)
        
        # Right panel - Details
        right_panel = self.create_right_panel()
        content_layout.addWidget(right_panel, 2)
        
        main_layout.addLayout(content_layout)
        
        # 3. Bottom panel - Alerts
        bottom_panel = self.create_bottom_panel()
        main_layout.addWidget(bottom_panel, 1)
        
        # 4. Status bar
        self.create_status_bar()
    
    def create_top_bar(self) -> QFrame:
        """Create top control bar with title and mode selector."""
        bar = GlowFrame(COLORS['neon_green'])
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Title
        title = QLabel("█ KEYBOARD TRANSPARENCY MONITOR")
        title.setStyleSheet(f"color: {COLORS['neon_cyan']}; font-family: 'Courier New'; font-size: 14px; font-weight: bold; background: transparent;")
        layout.addWidget(title)
        
        # Status indicator
        self.status_indicator = StatusIndicator("SCANNING", COLORS['neon_green'])
        layout.addWidget(self.status_indicator)
        
        # Mode selector
        mode_label = QLabel("[MODE]")
        mode_label.setStyleSheet(f"color: {COLORS['neon_green']}; font-family: 'Courier New'; font-size: 10px; background: transparent;")
        layout.addWidget(mode_label)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["NORMAL", "PRIVACY-FOCUSED", "SECURITY-EXPERT"])
        layout.addWidget(self.mode_combo)
        
        # Refresh button
        refresh_btn = NeonButton("⟳ REFRESH", style="default")
        refresh_btn.setMaximumWidth(120)
        refresh_btn.clicked.connect(self.refresh_scan)
        layout.addWidget(refresh_btn)
        
        # Scan toggle
        self.scan_toggle = NeonButton("⊙ START SCAN", style="default")
        self.scan_toggle.setMaximumWidth(120)
        self.scan_toggle.clicked.connect(self.toggle_scan)
        layout.addWidget(self.scan_toggle)
        
        return bar
    
    def create_left_panel(self) -> QFrame:
        """Create left process monitor panel."""
        panel = GlowFrame(COLORS['neon_green'])
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Header
        header = QLabel("▌ PROCESS MONITOR")
        header.setStyleSheet(f"color: {COLORS['neon_green']}; font-family: 'Courier New'; font-size: 11px; font-weight: bold; background: transparent;")
        layout.addWidget(header)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["NAME", "PID", "RISK", "STATUS", "ACTION"])
        self.process_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.setSelectionMode(QTableWidget.SingleSelection)
        self.process_table.itemSelectionChanged.connect(self.on_process_selected)
        self.process_table.setStyleSheet(MONITOR_STYLESHEET)
        
        layout.addWidget(self.process_table)
        
        # Total processes label
        self.proc_count_label = QLabel("PROCESSES DETECTED: 0")
        self.proc_count_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-family: 'Courier New'; font-size: 9px; background: transparent;")
        layout.addWidget(self.proc_count_label)
        
        return panel
    
    def create_center_panel(self) -> QFrame:
        """Create center scanner visualization panel."""
        panel = GlowFrame(COLORS['neon_cyan'])
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Header
        header = QLabel("▌ SYSTEM SCAN")
        header.setStyleSheet(f"color: {COLORS['neon_cyan']}; font-family: 'Courier New'; font-size: 11px; font-weight: bold; background: transparent;")
        layout.addWidget(header)
        
        # Scanner visualization
        self.scanner = ScannerIndicator()
        self.scanner.set_scanning(True)
        layout.addWidget(self.scanner, alignment=Qt.AlignCenter)
        
        # Activity waveform
        self.activity_wave = ActivityWave()
        self.activity_wave.start_animation()
        layout.addWidget(self.activity_wave)
        
        # Stats
        stats_frame = QFrame()
        stats_layout = QVBoxLayout(stats_frame)
        stats_layout.setContentsMargins(5, 5, 5, 5)
        
        self.threat_count = QLabel("SUSPICIOUS: 0")
        self.threat_count.setStyleSheet(f"color: {COLORS['danger_red']}; font-family: 'Courier New'; font-size: 10px; background: transparent;")
        stats_layout.addWidget(self.threat_count)
        
        self.alert_count = QLabel("ALERTS: 0")
        self.alert_count.setStyleSheet(f"color: {COLORS['warning_yellow']}; font-family: 'Courier New'; font-size: 10px; background: transparent;")
        stats_layout.addWidget(self.alert_count)
        
        layout.addWidget(stats_frame)
        
        return panel
    
    def create_right_panel(self) -> QFrame:
        """Create right process details panel."""
        panel = GlowFrame(COLORS['neon_purple'])
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Header
        header = QLabel("▌ PROCESS DETAILS")
        header.setStyleSheet(f"color: {COLORS['neon_purple']}; font-family: 'Courier New'; font-size: 11px; font-weight: bold; background: transparent;")
        layout.addWidget(header)
        
        # Scrollable details area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        details_widget = QWidget()
        self.details_layout = QVBoxLayout(details_widget)
        self.details_layout.setContentsMargins(5, 5, 5, 5)
        scroll.setWidget(details_widget)
        layout.addWidget(scroll)
        
        # Placeholder
        placeholder = QLabel("▸ SELECT PROCESS FOR DETAILS")
        placeholder.setStyleSheet(f"color: {COLORS['text_secondary']}; font-family: 'Courier New'; font-size: 9px; background: transparent;")
        self.details_layout.addWidget(placeholder)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.trust_btn = NeonButton("✓ TRUST", style="default")
        self.trust_btn.setEnabled(False)
        self.trust_btn.clicked.connect(self.on_trust_clicked)
        btn_layout.addWidget(self.trust_btn)
        
        self.block_btn = NeonButton("✕ BLOCK", style="danger")
        self.block_btn.setEnabled(False)
        self.block_btn.clicked.connect(self.on_block_clicked)
        btn_layout.addWidget(self.block_btn)
        
        layout.addLayout(btn_layout)
        
        return panel
    
    def create_bottom_panel(self) -> QFrame:
        """Create bottom alerts and timeline panel."""
        panel = GlowFrame(COLORS['neon_green'])
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 5, 8, 5)
        
        # Header
        header = QLabel("▌ ALERTS & TIMELINE")
        header.setStyleSheet(f"color: {COLORS['neon_green']}; font-family: 'Courier New'; font-size: 11px; font-weight: bold; background: transparent;")
        layout.addWidget(header, 0)
        
        # Timeline table
        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(4)
        self.timeline_table.setHorizontalHeaderLabels(["TIME", "EVENT", "SEVERITY", "DETAILS"])
        self.timeline_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.timeline_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.timeline_table.setMaximumHeight(120)
        self.timeline_table.setStyleSheet(MONITOR_STYLESHEET)
        
        layout.addWidget(self.timeline_table, 1)
        
        return panel
    
    def create_status_bar(self):
        """Create cyberpunk status bar."""
        status_bar = self.statusBar()
        status_bar.setStyleSheet(f"background-color: {COLORS['bg_panel']}; color: {COLORS['text_secondary']}; border-top: 1px solid {COLORS['neon_green']};")
        status_bar.showMessage("█ SYSTEM ONLINE | MONITOR ACTIVE")
    
    def add_process_to_table(self, name: str, pid: int, risk_level: int, status: str = "MONITORING"):
        """Add a process to the monitor table (avoid duplicates)."""
        # Check if process already in table
        for row in range(self.process_table.rowCount()):
            existing_pid = self.process_table.item(row, 1).text()
            if str(pid) == existing_pid:
                # Update risk level if it changed
                risk_item = self.process_table.item(row, 2)
                risk_item.setText(f"{risk_level}%")
                
                # Update color
                if risk_level < 30:
                    risk_item.setForeground(QColor(COLORS['neon_green']))
                elif risk_level < 60:
                    risk_item.setForeground(QColor(COLORS['warning_yellow']))
                else:
                    risk_item.setForeground(QColor(COLORS['danger_red']))
                return
        
        # New process - add to table
        row = self.process_table.rowCount()
        self.process_table.insertRow(row)
        
        # Name
        item = QTableWidgetItem(name)
        self.process_table.setItem(row, 0, item)
        
        # PID
        item = QTableWidgetItem(str(pid))
        self.process_table.setItem(row, 1, item)
        
        # Risk level with color
        item = QTableWidgetItem(f"{risk_level}%")
        if risk_level < 30:
            item.setForeground(QColor(COLORS['neon_green']))
        elif risk_level < 60:
            item.setForeground(QColor(COLORS['warning_yellow']))
        else:
            item.setForeground(QColor(COLORS['danger_red']))
        self.process_table.setItem(row, 2, item)
        
        # Status
        item = QTableWidgetItem(status)
        self.process_table.setItem(row, 3, item)
        
        # Action (placeholder)
        item = QTableWidgetItem("...")
        self.process_table.setItem(row, 4, item)
        
        # Update process count
        self.proc_count_label.setText(f"PROCESSES DETECTED: {self.process_table.rowCount()}")
    
    def add_alert_to_timeline(self, timestamp: str, event: str, severity: str, details: str):
        """Add an alert to the timeline."""
        row = self.timeline_table.rowCount()
        self.timeline_table.insertRow(row)
        
        # Time
        item = QTableWidgetItem(timestamp)
        self.timeline_table.setItem(row, 0, item)
        
        # Event
        item = QTableWidgetItem(event)
        self.timeline_table.setItem(row, 1, item)
        
        # Severity with color
        item = QTableWidgetItem(severity)
        if severity == "CRITICAL":
            item.setForeground(QColor(COLORS['danger_red']))
        elif severity == "WARNING":
            item.setForeground(QColor(COLORS['warning_yellow']))
        else:
            item.setForeground(QColor(COLORS['neon_green']))
        self.timeline_table.setItem(row, 2, item)
        
        # Details
        item = QTableWidgetItem(details)
        self.timeline_table.setItem(row, 3, item)
        
        # Scroll to bottom
        self.timeline_table.scrollToBottom()
        
        # Keep only last 50 events
        while self.timeline_table.rowCount() > 50:
            self.timeline_table.removeRow(0)
    
    def show_process_details(self, process_name: str, process_path: str, risk_level: int, 
                            risk_reasons: list, confidence: int):
        """Display process details in the right panel."""
        # Clear previous details
        while self.details_layout.count() > 0:
            self.details_layout.takeAt(0).widget().deleteLater()
        
        # Process name
        name_label = QLabel(f"PROCESS: {process_name}")
        name_label.setStyleSheet(f"color: {COLORS['neon_cyan']}; font-family: 'Courier New'; font-size: 10px; font-weight: bold; background: transparent;")
        self.details_layout.addWidget(name_label)
        
        # Path
        path_label = QLabel(f"PATH: {process_path}")
        path_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-family: 'Courier New'; font-size: 8px; background: transparent;")
        path_label.setWordWrap(True)
        self.details_layout.addWidget(path_label)
        
        # Risk indicator
        self.details_layout.addWidget(QLabel(""))
        risk_ind = RiskIndicator()
        risk_ind.set_risk(risk_level)
        self.details_layout.addWidget(risk_ind)
        
        # Confidence bar
        conf_bar = ConfidenceBar()
        conf_bar.set_confidence(confidence)
        self.details_layout.addWidget(conf_bar)
        
        # Risk reasons
        self.details_layout.addWidget(QLabel(""))
        reasons_label = QLabel("DETECTION SIGNALS:")
        reasons_label.setStyleSheet(f"color: {COLORS['neon_green']}; font-family: 'Courier New'; font-size: 9px; font-weight: bold; background: transparent;")
        self.details_layout.addWidget(reasons_label)
        
        for reason in risk_reasons:
            reason_label = QLabel(f"  • {reason}")
            reason_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-family: 'Courier New'; font-size: 8px; background: transparent;")
            self.details_layout.addWidget(reason_label)
        
        self.details_layout.addStretch()
    
    def on_process_selected(self):
        """Handle process selection."""
        selected_rows = self.process_table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            process_name = self.process_table.item(row, 0).text()
            self.selected_process = process_name
            
            # Show details and enable buttons
            self.trust_btn.setEnabled(True)
            self.block_btn.setEnabled(True)
            
            # Show example details
            self.show_process_details(
                process_name,
                f"C:\\Program Files\\...\\{process_name}.exe",
                int(self.process_table.item(row, 2).text().rstrip('%')),
                [
                    "Input device access detected",
                    "Suspicious process name",
                    "Non-standard installation path"
                ],
                75
            )
    
    def on_trust_clicked(self):
        """Handle trust button click."""
        if self.selected_process:
            self.add_alert_to_timeline(
                self.get_timestamp(), 
                "PROCESS TRUSTED",
                "INFO",
                f"{self.selected_process} added to trust list"
            )
            self.process_trusted.emit(self.selected_process)
    
    def on_block_clicked(self):
        """Handle block button click."""
        if self.selected_process:
            self.add_alert_to_timeline(
                self.get_timestamp(),
                "PROCESS BLOCKED",
                "CRITICAL",
                f"{self.selected_process} - execution prevented"
            )
            self.process_blocked.emit(self.selected_process)
    
    def refresh_scan(self):
        """Refresh the process scan."""
        if self.app_context and hasattr(self.app_context, 'monitor_service'):
            # Trigger manual scan through monitor service
            self.app_context.monitor_service.pause()
            # Quick scan all processes now
            processes = self.app_context.scanner.scan_all_processes()
            print(f"[UI.refresh_scan] Scanned {len(processes)} processes")
            for proc in processes:
                assessment = self.app_context.risk_engine.analyze(proc)
                self.on_process_detected(proc, assessment)
            self.app_context.monitor_service.resume()
        
        self.add_alert_to_timeline(
            self.get_timestamp(),
            "MANUAL REFRESH",
            "INFO",
            "System scan initiated"
        )
    
    def auto_start_scan(self):
        """Auto-start scanning when application starts."""
        print("[UI.auto_start_scan] Triggering auto-start")
        self.toggle_scan()  # This will START the scan
    
    def toggle_scan(self):
        """Toggle scanning state - START/STOP actual monitor service."""
        if not self.app_context or not hasattr(self.app_context, 'monitor_service'):
            self.add_alert_to_timeline(
                self.get_timestamp(),
                "ERROR",
                "CRITICAL",
                "Monitor service not initialized"
            )
            return
        
        monitor = self.app_context.monitor_service
        
        if self.scan_toggle.text() == "⊙ START SCAN":
            # START scanning
            if not monitor.is_running():
                monitor.start()
            monitor.resume()
            
            self.scan_toggle.setText("● STOP SCAN")
            self.status_indicator.set_status("SCANNING", COLORS['neon_green'])
            self.scanner.set_scanning(True)
            self.activity_wave.start_animation()
            
            self.add_alert_to_timeline(
                self.get_timestamp(),
                "SYSTEM ONLINE",
                "INFO",
                "Monitoring service started"
            )
        else:
            # STOP scanning
            monitor.pause()
            
            self.scan_toggle.setText("⊙ START SCAN")
            self.status_indicator.set_status("IDLE", COLORS['neon_green'])
            self.scanner.set_scanning(False)
            self.activity_wave.stop_animation()
            
            self.add_alert_to_timeline(
                self.get_timestamp(),
                "SYSTEM OFFLINE",
                "INFO",
                "Monitoring service paused"
            )
    
    def update_demo_data(self):
        """Update table with demo data."""
        import random
        if self.process_table.rowCount() < 7:
            processes = [
                ("keylogger.exe", 1234, 95),
                ("inputdevice.exe", 5678, 88),
                ("kbdhook.exe", 9012, 75),
                ("spysystem.exe", 3456, 82),
                ("monitor.exe", 7890, 45),
                ("explorer.exe", 2345, 12),
                ("chrome.exe", 6789, 28),
            ]
            for name, pid, risk in processes:
                if self.process_table.rowCount() <= len(processes):
                    self.add_process_to_table(name, pid, risk)
            
            # Add initial alerts
            if self.timeline_table.rowCount() == 0:
                self.add_alert_to_timeline("00:12:34.123", "SYSTEM ONLINE", "INFO", "Keyboard Transparency Monitor activated")
                self.add_alert_to_timeline("00:12:35.456", "SCAN STARTED", "INFO", "Initial system scan in progress")
                self.add_alert_to_timeline("00:12:37.789", "THREAT DETECTED", "CRITICAL", "keylogger.exe - Input device access")
    
    @staticmethod
    def get_timestamp():
        """Get current timestamp in HH:MM:SS.mmm format."""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    def on_alert_generated(self, alert):
        """Handle alert generated by monitor service."""
        if alert:
            # Add alert to timeline
            severity_str = alert.severity.value if hasattr(alert.severity, 'value') else str(alert.severity)
            self.add_alert_to_timeline(
                self.get_timestamp(),
                alert.title if hasattr(alert, 'title') else "ALERT",
                severity_str,
                alert.message if hasattr(alert, 'message') else str(alert)
            )
    
    def on_process_detected(self, process, assessment):
        """Thread-safe wrapper: emit signal from background thread."""
        print(f"[UI.on_process_detected] Called from thread: {process.name if process else 'None'}")
        self.signals.process_detected.emit(process, assessment)

    def _on_process_detected_safe(self, process, assessment):
        """Handle process detected by monitor service (main thread)."""
        print(f"[UI._on_process_detected_safe] Called: {process.name if process else 'None'}")
        if assessment:
            # Add process to table if not already there
            pid = assessment.pid if hasattr(assessment, 'pid') else None
            process_name = assessment.process_name if hasattr(assessment, 'process_name') else "Unknown"
            risk_score = int(assessment.risk_score) if hasattr(assessment, 'risk_score') else 0
            
            print(f"[UI] Adding process: {process_name} (PID {pid}, risk={risk_score})")
            
            # Check if this is a suspicious process (keyboard access detected)
            is_dangerous = risk_score >= 70
            
            if pid and process_name:
                self.add_process_to_table(process_name, pid, risk_score)
                
                # Generate alert for high-risk processes
                if is_dangerous:
                    keyboard_indicators = ""
                    if hasattr(assessment, 'keyboard_related_indicators') and assessment.keyboard_related_indicators:
                        keyboard_indicators = ", ".join(str(i) for i in assessment.keyboard_related_indicators[:2])
                    
                    severity = "CRITICAL" if risk_score >= 85 else "WARNING"
                    self.add_alert_to_timeline(
                        self.get_timestamp(),
                        f"THREAT DETECTED: {process_name}",
                        severity,
                        f"Risk score: {risk_score}% - {keyboard_indicators or 'Suspicious behavior detected'}"
                    )
                    
                    # Update threat counter
                    try:
                        current_text = self.threat_count.text()
                        threat_count = int(current_text.split()[-1]) + 1
                        self.threat_count.setText(f"SUSPICIOUS: {threat_count}")
                    except:
                        pass

    def on_alert_generated(self, process, assessment, alert):
        """Thread-safe wrapper: emit signal from background thread."""
        print(f"[UI.on_alert_generated] Called")
        self.signals.alert_generated.emit(process, assessment, alert)

    def _on_alert_generated_safe(self, process, assessment, alert):
        """Handle alert generated by monitor service (main thread)."""
        print(f"[UI._on_alert_generated_safe] Called")
        if alert:
            # Add alert to timeline
            severity_str = str(alert.severity.value) if hasattr(alert, 'severity') and hasattr(alert.severity, 'value') else "INFO"
            message = alert.message if hasattr(alert, 'message') else str(alert)
            self.add_alert_to_timeline(
                self.get_timestamp(),
                alert.title if hasattr(alert, 'title') else "ALERT",
                severity_str,
                message
            )
    
    def closeEvent(self, event):
        """Handle window close."""
        if hasattr(self, 'demo_timer'):
            self.demo_timer.stop()
        event.accept()


# Compatibility alias for existing imports
MainWindow = CyberpunkMainWindow
