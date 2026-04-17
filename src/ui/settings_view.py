"""Settings view."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QDoubleSpinBox, QCheckBox, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Signal
from PySide6.QtGui import QFont


class SettingsView(QWidget):
    """Application settings and configuration."""

    scan_interval_changed = Signal(float)
    show_low_risk_changed = Signal(bool)
    add_trusted_process = Signal()
    remove_trusted_process = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build settings layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # Title
        title = QLabel("Settings")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Scan settings
        scan_group = QGroupBox("Scanning")
        scan_layout = QVBoxLayout()

        interval_layout = QHBoxLayout()
        interval_label = QLabel("Scan Interval (seconds):")
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setMinimum(2.0)
        self.interval_spin.setMaximum(300.0)
        self.interval_spin.setValue(10.0)
        self.interval_spin.setSingleStep(1.0)
        self.interval_spin.valueChanged.connect(self._on_interval_changed)
        interval_layout.addWidget(interval_label)
        interval_layout.addWidget(self.interval_spin)
        interval_layout.addStretch()
        scan_layout.addLayout(interval_layout)

        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)

        # Display settings
        display_group = QGroupBox("Display")
        display_layout = QVBoxLayout()

        self.show_low_risk_check = QCheckBox("Show Low-Risk Processes")
        self.show_low_risk_check.setChecked(False)
        self.show_low_risk_check.stateChanged.connect(self._on_show_low_risk_changed)
        display_layout.addWidget(self.show_low_risk_check)

        display_group.setLayout(display_layout)
        layout.addWidget(display_group)

        # Trusted processes
        trusted_group = QGroupBox("Trusted Processes")
        trusted_layout = QVBoxLayout()

        trusted_label = QLabel("Processes marked as trusted will not be flagged:")
        trusted_layout.addWidget(trusted_label)

        self.trusted_list = QListWidget()
        self.trusted_list.setMaximumHeight(150)
        trusted_layout.addWidget(self.trusted_list)

        trusted_btn_layout = QHBoxLayout()
        add_trusted_btn = QPushButton("Add Process")
        add_trusted_btn.clicked.connect(self.add_trusted_process.emit)
        trusted_btn_layout.addWidget(add_trusted_btn)

        remove_trusted_btn = QPushButton("Remove Selected")
        remove_trusted_btn.clicked.connect(self._on_remove_trusted_clicked)
        trusted_btn_layout.addWidget(remove_trusted_btn)

        trusted_btn_layout.addStretch()
        trusted_layout.addLayout(trusted_btn_layout)

        trusted_group.setLayout(trusted_layout)
        layout.addWidget(trusted_group)

        # Info
        info_group = QGroupBox("Information")
        info_layout = QVBoxLayout()

        info_text = QLabel(
            "<b>About:</b> Keyboard Transparency Monitor is a heuristic-based process "
            "monitoring tool designed to identify suspicious process behavior.\n\n"
            "<b>Privacy:</b> This application does NOT capture, store, or transmit actual "
            "keyboard input or sensitive data. Only process metadata is monitored.\n\n"
            "<b>Detection Method:</b> Uses observable signals and heuristics such as process "
            "age, resource usage, path analysis, and naming patterns."
        )
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        layout.addStretch()

    def set_scan_interval(self, interval: float) -> None:
        """Set the scan interval value."""
        self.interval_spin.blockSignals(True)
        self.interval_spin.setValue(interval)
        self.interval_spin.blockSignals(False)

    def set_trusted_processes(self, processes: set) -> None:
        """Update trusted processes list."""
        self.trusted_list.clear()
        for process in sorted(processes):
            item = QListWidgetItem(process)
            self.trusted_list.addItem(item)

    def _on_interval_changed(self, value: float) -> None:
        """Handle scan interval change."""
        self.scan_interval_changed.emit(value)

    def _on_show_low_risk_changed(self, state) -> None:
        """Handle show low-risk toggle."""
        self.show_low_risk_changed.emit(self.show_low_risk_check.isChecked())

    def _on_remove_trusted_clicked(self) -> None:
        """Handle remove trusted process."""
        selected = self.trusted_list.selectedItems()
        if selected:
            process_name = selected[0].text()
            self.remove_trusted_process.emit(process_name)
