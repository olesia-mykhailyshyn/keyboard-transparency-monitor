#!/usr/bin/env python3
"""
Keyboard Transparency Monitor - Main application entry point.

This application monitors local processes and helps users understand
which processes may be accessing or behaving as if they could access
keyboard-related input.

PRIVACY GUARANTEE: This app does NOT capture, store, or read actual keystrokes.
It only analyzes process metadata and behavior patterns.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt

# Import core services
from core.process_scanner import ProcessScanner
from core.risk_engine import RiskEngine
from core.blocklist_service import BlocklistService
from core.trust_service import TrustService
from core.alert_manager import AlertManager
from core.user_action_logger import UserActionLogger
from core.monitor_service import MonitorService

# Import storage
from storage.database import initialize_database, get_db_connection
from storage.repositories import (
    DetectionRepository,
    BlocklistRepository,
    TrustlistRepository,
    AlertRepository,
    UserActionRepository,
    StatisticsRepository,
)

# Import UI - Cyberpunk surveillance-style interface
from ui.cyberpunk_main_window import MainWindow

# Import demo simulator
from demo.simulator import ProcessSimulator

# Import platform adapter
from platform import get_platform_adapter


class Application:
    """Main application orchestrator."""

    def __init__(self, demo_mode: bool = False):
        """
        Initialize the application.
        
        Args:
            demo_mode: If True, run in safe demo mode with simulated processes
        """
        self.demo_mode = demo_mode
        self.db_connection = None
        
        # Initialize services
        self.initialize_services()

    def initialize_services(self):
        """Initialize all core services."""
        # Database setup
        db_path = self._get_db_path()
        self.db_connection = initialize_database(db_path)

        # Repositories
        self.repos = {
            'detection': DetectionRepository(self.db_connection),
            'blocklist': BlocklistRepository(self.db_connection),
            'trustlist': TrustlistRepository(self.db_connection),
            'alerts': AlertRepository(self.db_connection),
            'actions': UserActionRepository(self.db_connection),
            'statistics': StatisticsRepository(self.db_connection),
        }

        # Core services
        self.scanner = ProcessScanner(include_system=True)
        self.risk_engine = RiskEngine()
        self.blocklist_service = BlocklistService(self.repos['blocklist'])
        self.trust_service = TrustService(self.repos['trustlist'])
        self.alert_manager = AlertManager(self.repos['alerts'])
        self.action_logger = UserActionLogger(self.repos['actions'])

        # Monitor service (background scanning)
        self.monitor_service = MonitorService(
            process_scanner=self.scanner,
            risk_engine=self.risk_engine,
            blocklist_service=self.blocklist_service,
            trust_service=self.trust_service,
            alert_manager=self.alert_manager,
            action_logger=self.action_logger,
            scan_interval=5.0,  # 5 seconds
        )

        # Platform adapter
        try:
            self.platform_adapter = get_platform_adapter()
        except RuntimeError as e:
            print(f"Warning: {e}")
            self.platform_adapter = None

        # Demo simulator (if enabled)
        if self.demo_mode:
            self.simulator = ProcessSimulator(
                scanner=self.scanner,
                risk_engine=self.risk_engine,
                alert_manager=self.alert_manager,
            )
        else:
            self.simulator = None

    def _get_db_path(self) -> str:
        """Get database file path, creating directory if needed."""
        db_dir = Path.home() / '.ktm'
        db_dir.mkdir(exist_ok=True)
        return str(db_dir / 'ktm.db')

    def run(self):
        """Start the application."""
        from ui.cyberpunk_styles import MAIN_STYLESHEET
        
        # Create Qt application
        app = QApplication(sys.argv)
        
        # Set application style and information
        app.setApplicationName("Keyboard Transparency Monitor")
        app.setApplicationVersion("0.1.0")
        app.setStyle('Fusion')  # Modern cross-platform style
        
        # Apply cyberpunk theme globally
        app.setStyleSheet(MAIN_STYLESHEET)

        # Create main window
        main_window = MainWindow(
            app_context=self,
            demo_mode=self.demo_mode,
        )

        # Start background monitor service
        self.monitor_service.start()

        # Register callbacks for real-time updates
        self.monitor_service.register_on_alert_generated(
            main_window.on_alert_generated
        )
        self.monitor_service.register_on_process_detected(
            main_window.on_process_detected
        )

        # Show window
        main_window.show()

        # Execute application
        sys.exit(app.exec())

    def cleanup(self):
        """Cleanup resources before exit."""
        if self.monitor_service and self.monitor_service.is_running():
            self.monitor_service.stop()

        if self.db_connection:
            try:
                self.db_connection.close()
            except Exception:
                pass


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Keyboard Transparency Monitor - Process Monitoring Tool"
    )
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run in demo mode with simulated processes (safe for testing)',
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging',
    )

    args = parser.parse_args()

    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Create and run application
    app = Application(demo_mode=args.demo)

    try:
        app.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        app.cleanup()


if __name__ == '__main__':
    main()
