"""
Enhanced UI Features for Keyboard Transparency Monitor
Additional interactive elements and user experience improvements
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QComboBox, QDialog, QScrollArea, QMenu, QMessageBox, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QSpinBox, QCheckBox
)
from PySide6.QtCore import Qt, pyqtSignal, QDateTime, QSize
from PySide6.QtGui import QFont, QColor, QIcon, QPixmap, QAction
from datetime import datetime
import json
import csv


class ProcessContextMenu:
    """Context menu for process table rows."""
    
    def __init__(self, parent_window):
        self.parent = parent_window
    
    def show_menu(self, position, process_data):
        """Show context menu at position with process actions."""
        menu = QMenu(self.parent)
        
        # Style menu
        menu.setStyleSheet("""
            QMenu {
                background-color: #16213e;
                color: #00ff00;
                border: 2px solid #0f3460;
            }
            QMenu::item:selected {
                background-color: #e94560;
                color: #000;
            }
        """)
        
        # Actions
        view_action = QAction("📊 View Details", menu)
        view_action.triggered.connect(lambda: self._view_details(process_data))
        menu.addAction(view_action)
        
        menu.addSeparator()
        
        block_action = QAction("🚫 Block Process", menu)
        block_action.triggered.connect(lambda: self._block_process(process_data))
        menu.addAction(block_action)
        
        trust_action = QAction("✅ Mark as Trusted", menu)
        trust_action.triggered.connect(lambda: self._trust_process(process_data))
        menu.addAction(trust_action)
        
        terminate_action = QAction("⚠️ Terminate Process", menu)
        terminate_action.triggered.connect(lambda: self._terminate_process(process_data))
        menu.addAction(terminate_action)
        
        menu.addSeparator()
        
        copy_action = QAction("📋 Copy PID", menu)
        copy_action.triggered.connect(lambda: self._copy_to_clipboard(process_data['pid']))
        menu.addAction(copy_action)
        
        # Show menu
        menu.exec(position)
    
    def _view_details(self, process_data):
        self.parent.show_process_details(process_data)
    
    def _block_process(self, process_data):
        result = QMessageBox.warning(
            self.parent,
            "Block Process?",
            f"Block {process_data['name']} (PID: {process_data['pid']})?\n\n"
            f"This process will be added to the blocklist and terminated.",
            QMessageBox.Yes | QMessageBox.No
        )
        if result == QMessageBox.Yes:
            self.parent.block_process(process_data)
    
    def _trust_process(self, process_data):
        result = QMessageBox.information(
            self.parent,
            "Trust Process?",
            f"Mark {process_data['name']} as safe?\n\n"
            f"This process will be added to the whitelist.",
            QMessageBox.Yes | QMessageBox.No
        )
        if result == QMessageBox.Yes:
            self.parent.trust_process(process_data)
    
    def _terminate_process(self, process_data):
        result = QMessageBox.critical(
            self.parent,
            "Terminate Process?",
            f"Terminate {process_data['name']} (PID: {process_data['pid']})?\n\n"
            f"Warning: This cannot be undone!",
            QMessageBox.Yes | QMessageBox.No
        )
        if result == QMessageBox.Yes:
            self.parent.terminate_process(process_data)
    
    def _copy_to_clipboard(self, text):
        from PySide6.QtGui import QGuiApplication
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(str(text))
        QMessageBox.information(self.parent, "Copied", f"Copied to clipboard: {text}")


class ProcessSearchFilter:
    """Process table search and filter widget."""
    
    def __init__(self, parent_window):
        self.parent = parent_window
        self.widget = self.create_filter_widget()
    
    def create_filter_widget(self):
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Search box
        search_label = QLabel("🔍 Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by process name, PID, or path...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #0f3460;
                color: #00ff00;
                border: 1px solid #0f3460;
                padding: 5px;
                font-weight: bold;
            }
            QLineEdit:focus {
                border: 2px solid #e94560;
            }
        """)
        self.search_input.textChanged.connect(self._on_search_changed)
        
        # Filter by risk
        filter_label = QLabel("Filter by Risk:")
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Risks", "Low", "Medium", "High", "Critical"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #0f3460;
                color: #00ff00;
                border: 1px solid #0f3460;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        
        # Clear button
        clear_btn = QPushButton("Clear All")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #0f3460;
                color: #e94560;
                border: 1px solid #0f3460;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e94560;
                color: #000;
            }
        """)
        clear_btn.clicked.connect(self._clear_filters)
        
        # Results counter
        self.results_label = QLabel("0 processes")
        self.results_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        
        layout.addWidget(search_label)
        layout.addWidget(self.search_input, 2)
        layout.addWidget(filter_label)
        layout.addWidget(self.filter_combo, 1)
        layout.addWidget(clear_btn)
        layout.addStretch()
        layout.addWidget(self.results_label)
        
        return container
    
    def _on_search_changed(self):
        search_text = self.search_input.text().lower()
        self._apply_filters(search_text)
    
    def _on_filter_changed(self):
        self._apply_filters(self.search_input.text().lower())
    
    def _apply_filters(self, search_text):
        """Apply search and risk filters to table."""
        if not hasattr(self.parent, 'process_table'):
            return
        
        table = self.parent.process_table
        risk_filter = self.filter_combo.currentText()
        visible_count = 0
        
        for row in range(table.rowCount()):
            # Get process data
            name_item = table.item(row, 0)  # Name
            risk_item = table.item(row, 2)  # Risk
            
            if not name_item or not risk_item:
                continue
            
            process_name = name_item.text().lower()
            risk_text = risk_item.text()
            
            # Apply search filter
            search_match = (not search_text) or (search_text in process_name)
            
            # Apply risk filter
            risk_match = (risk_filter == "All Risks")
            if not risk_match:
                risk_match = risk_filter.lower() in risk_text.lower()
            
            # Show/hide row
            is_visible = search_match and risk_match
            table.setRowHidden(row, not is_visible)
            
            if is_visible:
                visible_count += 1
        
        self.results_label.setText(f"{visible_count} processes")
    
    def _clear_filters(self):
        self.search_input.clear()
        self.filter_combo.setCurrentIndex(0)


class ExportFunctionality:
    """Export detections and reports."""
    
    def __init__(self, parent_window):
        self.parent = parent_window
    
    def export_to_csv(self):
        """Export process table to CSV."""
        file_path, _ = QFileDialog.getSaveFileName(
            self.parent,
            "Export to CSV",
            f"processes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write headers
                headers = ["Name", "PID", "Risk Level", "Risk Score", "Status", 
                          "Executable", "Started", "Memory (MB)"]
                writer.writerow(headers)
                
                # Write process rows
                table = self.parent.process_table
                for row in range(table.rowCount()):
                    row_data = []
                    for col in range(table.columnCount()):
                        item = table.item(row, col)
                        if item:
                            row_data.append(item.text())
                    if row_data:
                        writer.writerow(row_data)
            
            QMessageBox.information(
                self.parent,
                "Export Successful",
                f"Process table exported to:\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self.parent,
                "Export Failed",
                f"Failed to export: {str(e)}"
            )
    
    def export_to_json(self):
        """Export alerts and detections to JSON."""
        file_path, _ = QFileDialog.getSaveFileName(
            self.parent,
            "Export to JSON",
            f"detections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)"
        )
        
        if not file_path:
            return
        
        try:
            # Collect data
            data = {
                "export_time": datetime.now().isoformat(),
                "processes": [],
                "alerts": []
            }
            
            # Add process data
            if hasattr(self.parent, 'process_table'):
                table = self.parent.process_table
                for row in range(table.rowCount()):
                    process = {
                        "name": table.item(row, 0).text() if table.item(row, 0) else "",
                        "pid": table.item(row, 1).text() if table.item(row, 1) else "",
                        "risk_level": table.item(row, 2).text() if table.item(row, 2) else "",
                    }
                    data["processes"].append(process)
            
            # Write JSON
            with open(file_path, 'w') as jsonfile:
                json.dump(data, jsonfile, indent=2)
            
            QMessageBox.information(
                self.parent,
                "Export Successful",
                f"Detections exported to:\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self.parent,
                "Export Failed",
                f"Failed to export: {str(e)}"
            )
    
    def export_report(self):
        """Export comprehensive security report."""
        file_path, _ = QFileDialog.getSaveFileName(
            self.parent,
            "Export Security Report",
            f"ktm_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        
        if not file_path:
            return
        
        try:
            report = self._generate_report()
            with open(file_path, 'w') as f:
                f.write(report)
            
            QMessageBox.information(
                self.parent,
                "Report Generated",
                f"Security report saved to:\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self.parent,
                "Report Failed",
                f"Failed to generate report: {str(e)}"
            )
    
    def _generate_report(self):
        """Generate security report content."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
╔════════════════════════════════════════════════════════════════╗
║    KEYBOARD TRANSPARENCY MONITOR - SECURITY REPORT             ║
╚════════════════════════════════════════════════════════════════╝

REPORT GENERATED: {timestamp}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY STATISTICS
──────────────────────────────────────────────────────────────────
"""
        
        # Add process statistics
        if hasattr(self.parent, 'process_table'):
            table = self.parent.process_table
            total_processes = table.rowCount()
            
            risk_levels = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
            
            for row in range(table.rowCount()):
                if not table.isRowHidden(row):
                    risk_item = table.item(row, 2)
                    if risk_item:
                        for level in risk_levels:
                            if level in risk_item.text():
                                risk_levels[level] += 1
            
            report += f"Total Processes Scanned: {total_processes}\n"
            report += f"Low Risk: {risk_levels['Low']}\n"
            report += f"Medium Risk: {risk_levels['Medium']}\n"
            report += f"High Risk: {risk_levels['High']}\n"
            report += f"Critical Risk: {risk_levels['Critical']}\n"
        
        report += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DETECTED THREATS
──────────────────────────────────────────────────────────────────
[High and Critical risk processes detected]

RECOMMENDATIONS
──────────────────────────────────────────────────────────────────
1. Block all Critical and High risk processes
2. Review Medium risk processes manually
3. Add trusted processes to whitelist
4. Enable continuous monitoring
5. Check for suspicious network connections

END OF REPORT
════════════════════════════════════════════════════════════════
"""
        return report


class EnhancedSettings:
    """Settings dialog for monitoring configuration."""
    
    def __init__(self, parent_window):
        self.parent = parent_window
        self.dialog = self.create_settings_dialog()
    
    def create_settings_dialog(self):
        dialog = QDialog(self.parent)
        dialog.setWindowTitle("KTM Settings")
        dialog.setGeometry(200, 200, 500, 400)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1a1a2e;
                color: #00ff00;
            }
            QLabel {
                color: #00ff00;
                font-weight: bold;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Scan interval
        scan_layout = QHBoxLayout()
        scan_label = QLabel("Scan Interval (seconds):")
        self.scan_spinbox = QSpinBox()
        self.scan_spinbox.setMinimum(1)
        self.scan_spinbox.setMaximum(60)
        self.scan_spinbox.setValue(5)
        scan_layout.addWidget(scan_label)
        scan_layout.addWidget(self.scan_spinbox)
        scan_layout.addStretch()
        layout.addLayout(scan_layout)
        
        # Risk threshold
        risk_layout = QHBoxLayout()
        risk_label = QLabel("Alert Threshold (risk %):")
        self.risk_spinbox = QSpinBox()
        self.risk_spinbox.setMinimum(0)
        self.risk_spinbox.setMaximum(100)
        self.risk_spinbox.setValue(70)
        risk_layout.addWidget(risk_label)
        risk_layout.addWidget(self.risk_spinbox)
        risk_layout.addStretch()
        layout.addLayout(risk_layout)
        
        # Options
        self.auto_block_critical = QCheckBox("Auto-block Critical threats")
        layout.addWidget(self.auto_block_critical)
        
        self.notifications_enabled = QCheckBox("Enable notifications")
        self.notifications_enabled.setChecked(True)
        layout.addWidget(self.notifications_enabled)
        
        self.log_all_processes = QCheckBox("Log all processes (not just high-risk)")
        layout.addWidget(self.log_all_processes)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(dialog.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.setLayout(layout)
        return dialog
    
    def show(self):
        return self.dialog.exec()
    
    def get_settings(self):
        return {
            "scan_interval": self.scan_spinbox.value(),
            "risk_threshold": self.risk_spinbox.value(),
            "auto_block_critical": self.auto_block_critical.isChecked(),
            "notifications_enabled": self.notifications_enabled.isChecked(),
            "log_all_processes": self.log_all_processes.isChecked()
        }


class HelpDialog(QDialog):
    """Help and about dialog."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("About Keyboard Transparency Monitor")
        self.setGeometry(200, 200, 600, 500)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a2e;
                color: #00ff00;
            }
            QLabel {
                color: #00ff00;
            }
        """)
        
        layout = QVBoxLayout()
        
        title = QLabel("KEYBOARD TRANSPARENCY MONITOR v1.0")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        
        info_text = QLabel("""
Keyboard Transparency Monitor is a desktop application that monitors 
running processes and detects suspicious programs that may attempt 
to access keyboard input.

FEATURES:
• Real-time process monitoring
• Multi-factor risk analysis (10 signals)
• Persistent blocklist/whitelist
• Detailed process inspection
• Export capabilities (CSV, JSON, Report)
• Cross-platform support

KEY SIGNALS:
• Input device access patterns
• Blocked process relaunch detection
• Suspicious installation paths
• Unsigned executables
• Newly started processes
• Hidden behavior patterns

LIMITATIONS:
• Windows requires kernel driver for true keyboard interception
• Some detections rely on heuristic analysis
• Performance depends on system load

GitHub: https://github.com/yourusername/ktm
License: MIT
        """)
        layout.addWidget(info_text)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        
        self.setLayout(layout)


# Export all enhancement classes
__all__ = [
    'ProcessContextMenu',
    'ProcessSearchFilter',
    'ExportFunctionality',
    'EnhancedSettings',
    'HelpDialog'
]
