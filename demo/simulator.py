"""Demo simulator for safe testing of UI with mock suspicious processes."""

from datetime import datetime, timedelta
from src.core.models import ProcessMetadata, RiskAssessment, RiskLevel, RiskSignal
import random


class ProcessSimulator:
    """Demo simulator for safe testing of UI with mock suspicious processes."""

    def __init__(self, scanner=None, risk_engine=None, alert_manager=None):
        """Initialize simulator with optional services for demo mode."""
        self.scanner = scanner
        self.risk_engine = risk_engine
        self.alert_manager = alert_manager

    @staticmethod
    def create_mock_detections() -> list:
        """Create mock suspicious processes for demo."""
        detections = []

        # Mock HIGH risk process
        high_risk = RiskAssessment(
            pid=9999,
            process_name="suspicious_app.exe",
            risk_level=RiskLevel.HIGH,
            risk_score=85.5,
            signals=[
                RiskSignal("newly_started", 1.0, "Process started 2 minutes ago"),
                RiskSignal("unusual_path", 0.8, "Executable in temp directory"),
                RiskSignal("no_visible_window", 0.6, "No visible UI window"),
            ],
            reasons=[
                "Process started 2 minutes ago",
                "Executable in suspicious directory: \\temp\\",
                "Process appears to run in background",
                "HEURISTIC-BASED: Detection may not be 100% accurate.",
            ],
            recommended_action="Recommend immediate investigation or termination.",
            timestamp=datetime.now() - timedelta(minutes=2),
        )
        detections.append(high_risk)

        # Mock MEDIUM risk process
        medium_risk = RiskAssessment(
            pid=8888,
            process_name="unknown_monitor.exe",
            risk_level=RiskLevel.MEDIUM,
            risk_score=55.0,
            signals=[
                RiskSignal("background_process", 0.5, "Background process with 12 threads"),
                RiskSignal("newly_started", 1.0, "Process started 5 minutes ago"),
            ],
            reasons=[
                "Process started 5 minutes ago",
                "Background process with 12 threads",
                "HEURISTIC-BASED: Detection may not be 100% accurate.",
            ],
            recommended_action="Review process details. Consider terminating if suspicious.",
            timestamp=datetime.now() - timedelta(minutes=5),
        )
        detections.append(medium_risk)

        return detections

    @staticmethod
    def create_mock_process_info() -> dict:
        """Create mock ProcessMetadata objects for demo."""
        return {
            9999: ProcessMetadata(
                pid=9999,
                name="suspicious_app.exe",
                executable_path="C:\\Users\\test\\AppData\\Local\\Temp\\suspicious_app.exe",
                command_line="C:\\Users\\test\\AppData\\Local\\Temp\\suspicious_app.exe -start",
                start_time=(datetime.now() - timedelta(minutes=2)).timestamp(),
                parent_pid=1234,
                parent_name="explorer.exe",
                user="test_user",
                num_threads=8,
                memory_mb=120.5,
                is_system_process=False,
            ),
            8888: ProcessMetadata(
                pid=8888,
                name="unknown_monitor.exe",
                executable_path="C:\\Windows\\temp\\unknown_monitor.exe",
                command_line="C:\\Windows\\temp\\unknown_monitor.exe",
                start_time=(datetime.now() - timedelta(minutes=5)).timestamp(),
                parent_pid=4,
                parent_name="system",
                user="SYSTEM",
                num_threads=12,
                memory_mb=85.2,
                is_system_process=False,
            ),
        }
