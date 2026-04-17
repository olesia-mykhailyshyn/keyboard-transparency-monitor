"""
Demo process simulator for safe testing and UI demonstration.

This module generates fake suspicious processes that mimic real keyboard
logger/spyware behavior for demonstration purposes WITHOUT actually
doing anything harmful.
"""

import random
import threading
from datetime import datetime, timedelta
from typing import List, Generator
from dataclasses import dataclass

from core.models import ProcessMetadata, RiskAssessment, RiskLevel, Alert, AlertSeverity
from core.process_scanner import ProcessScanner
from core.risk_engine import RiskEngine
from core.alert_manager import AlertManager


@dataclass
class SimulatedProcess:
    """A simulated suspicious process for demo mode."""
    name: str
    executable: str
    description: str
    risk_level: RiskLevel
    signals: List[str]
    keyboard_related: bool = False


class ProcessSimulator:
    """Generates simulated processes and detections for demo/testing."""

    # Simulated suspicious processes
    SIMULATED_PROCESSES = [
        SimulatedProcess(
            name="clipmonitor.exe",
            executable="C:\\Users\\User\\AppData\\Local\\clipmonitor.exe",
            description="Monitors clipboard activity",
            risk_level=RiskLevel.HIGH,
            signals=['unusual_path', 'newly_started', 'no_visible_window'],
            keyboard_related=False,
        ),
        SimulatedProcess(
            name="inputdevice.exe",
            executable="C:\\Temp\\inputdevice.exe",
            description="Attempts to access input device interfaces",
            risk_level=RiskLevel.CRITICAL,
            signals=['input_device_access', 'suspicious_path'],
            keyboard_related=True,
        ),
        SimulatedProcess(
            name="systemmonitor.exe",
            executable="C:\\Users\\User\\Downloads\\systemmonitor.exe",
            description="Monitors system activity in background",
            risk_level=RiskLevel.MEDIUM,
            signals=['suspicious_path', 'no_visible_window', 'high_threads'],
            keyboard_related=False,
        ),
        SimulatedProcess(
            name="kbdhook.exe",
            executable="C:\\Temp\\kbdhook.exe",
            description="Installs keyboard hooks for input capture",
            risk_level=RiskLevel.CRITICAL,
            signals=['input_device_access', 'suspicious_name', 'suspicious_path'],
            keyboard_related=True,
        ),
        SimulatedProcess(
            name="logger_service.exe",
            executable="C:\\Windows\\System32\\logger_service.exe",
            description="Logs user activities",
            risk_level=RiskLevel.HIGH,
            signals=['suspicious_name', 'high_handle_count'],
            keyboard_related=True,
        ),
        SimulatedProcess(
            name="hidden_monitor.exe",
            executable="C:\\ProgramData\\hidden_monitor.exe",
            description="Hidden background monitoring process",
            risk_level=RiskLevel.MEDIUM,
            signals=['no_visible_window', 'unusual_parent', 'hidden_behavior'],
            keyboard_related=False,
        ),
        SimulatedProcess(
            name="keylogger.exe",
            executable="C:\\Temp\\keylogger.exe",
            description="Captures keyboard input",
            risk_level=RiskLevel.CRITICAL,
            signals=['input_device_access', 'suspicious_name', 'suspicious_path'],
            keyboard_related=True,
        ),
    ]

    # Legitimate processes (for comparison)
    LEGIT_PROCESSES = [
        ("explorer.exe", "C:\\Windows\\explorer.exe", "Windows File Explorer"),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe", "Google Chrome Browser"),
        ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "Windows Notepad"),
        ("calc.exe", "C:\\Windows\\System32\\calc.exe", "Windows Calculator"),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "Windows Service Host"),
        ("dwm.exe", "C:\\Windows\\System32\\dwm.exe", "Desktop Window Manager"),
    ]

    def __init__(
        self,
        scanner: ProcessScanner,
        risk_engine: RiskEngine,
        alert_manager: AlertManager,
    ):
        """
        Initialize simulator.
        
        Args:
            scanner: ProcessScanner for creating fake metadata
            risk_engine: RiskEngine for analysis
            alert_manager: AlertManager for generating alerts
        """
        self.scanner = scanner
        self.risk_engine = risk_engine
        self.alert_manager = alert_manager
        self._simulated_pids = {}  # Track PID -> simulated process
        self._next_pid = 50000  # Start IDs from high number to avoid collisions

    def create_simulated_metadata(
        self,
        sim_process: SimulatedProcess,
    ) -> ProcessMetadata:
        """Create ProcessMetadata for a simulated process."""
        pid = self._get_next_pid()
        current_time = datetime.now()

        return ProcessMetadata(
            pid=pid,
            name=sim_process.name,
            executable=sim_process.executable,
            cmdline=f"{sim_process.executable} --no-ui --background",
            create_time=(current_time - timedelta(minutes=random.randint(1, 30))).timestamp(),
            is_system=False,
            memory_mb=random.uniform(15, 150),
            num_threads=random.randint(3, 20),
            executable_hash="simulated_hash_" + sim_process.name,
            parent_pid=random.choice([4, 8, 512, 1024]),  # Common parent PIDs
            parent_name=random.choice(["explorer.exe", "svchost.exe"]),
        )

    def generate_detection(
        self,
        sim_process: SimulatedProcess,
    ) -> tuple:
        """
        Generate a detection for a simulated process.
        
        Returns:
            (process_metadata, risk_assessment, alert)
        """
        metadata = self.create_simulated_metadata(sim_process)

        # Create risk assessment matching the simulated process
        assessment = RiskAssessment(
            pid=metadata.pid,
            process_name=metadata.name,
            executable_path=metadata.executable,
            risk_level=sim_process.risk_level,
            risk_score=self._level_to_score(sim_process.risk_level),
            detected_signals=sim_process.signals,
            input_device_detected=sim_process.keyboard_related,
            keyboard_related_indicators=self._get_keyboard_indicators(sim_process),
            confidence=0.85,
            recommendations=self._get_recommendations(sim_process.risk_level),
            timestamp=datetime.now(),
        )

        # Create alert
        alert = self.alert_manager.create_alert_from_assessment(
            assessment=assessment,
            process_name=metadata.name,
            details=f"[SIMULATED] {sim_process.description}",
        )

        return metadata, assessment, alert

    def generate_all_detections(self) -> Generator[tuple, None, None]:
        """
        Generate detections for all simulated processes.
        
        Yields:
            (process_metadata, risk_assessment, alert) tuples
        """
        for sim_process in self.SIMULATED_PROCESSES:
            yield self.generate_detection(sim_process)

    def generate_random_detections(self, count: int = 3) -> List[tuple]:
        """
        Generate random simulated detections.
        
        Args:
            count: Number of detections to generate
            
        Returns:
            List of (metadata, assessment, alert) tuples
        """
        detections = []
        for _ in range(min(count, len(self.SIMULATED_PROCESSES))):
            sim_process = random.choice(self.SIMULATED_PROCESSES)
            detections.append(self.generate_detection(sim_process))
        return detections

    def simulate_relaunch(self, original_pid: int) -> tuple:
        """
        Simulate a previously blocked process relaunching.
        
        Args:
            original_pid: PID of original blocked process
            
        Returns:
            (process_metadata, risk_assessment, alert) for relaunch
        """
        sim_process = SimulatedProcess(
            name="relaunched_process.exe",
            executable="C:\\Temp\\suspicious_tool.exe",
            description="Previously blocked process attempting to restart",
            risk_level=RiskLevel.CRITICAL,
            signals=['blocked_process_relaunch', 'input_device_access'],
            keyboard_related=True,
        )

        metadata = self.create_simulated_metadata(sim_process)
        metadata.pid = original_pid  # Use same PID pattern

        assessment = RiskAssessment(
            pid=metadata.pid,
            process_name=metadata.name,
            executable_path=metadata.executable,
            risk_level=RiskLevel.CRITICAL,
            risk_score=100,
            detected_signals=['blocked_process_relaunch'],
            input_device_detected=True,
            keyboard_related_indicators=["Relaunch of blocked process"],
            confidence=1.0,
            recommendations=[
                "🔴 CRITICAL: Previously blocked process detected relaunching.",
                "Consider auto-termination or permanent blocklist entry.",
            ],
            timestamp=datetime.now(),
        )

        alert = self.alert_manager.create_alert_from_assessment(
            assessment=assessment,
            process_name=metadata.name,
            details="[SIMULATED RELAUNCH] Blocked process attempting restart",
        )

        return metadata, assessment, alert

    def start_continuous_simulation(self, interval: float = 15.0):
        """
        Start a background thread that continuously generates random detections.
        
        Args:
            interval: Time between simulated events (seconds)
        """
        def _simulation_loop():
            while True:
                try:
                    # Randomly generate a detection
                    detections = self.generate_random_detections(1)
                    # In real UI, this would trigger callbacks
                    threading.Event().wait(interval)
                except Exception:
                    pass

        thread = threading.Thread(target=_simulation_loop, daemon=True)
        thread.start()

    def _get_next_pid(self) -> int:
        """Get next simulated PID."""
        pid = self._next_pid
        self._next_pid += 1
        return pid

    @staticmethod
    def _level_to_score(level: RiskLevel) -> int:
        """Convert risk level to score."""
        return {
            RiskLevel.LOW: 25,
            RiskLevel.MEDIUM: 55,
            RiskLevel.HIGH: 75,
            RiskLevel.CRITICAL: 95,
        }.get(level, 50)

    @staticmethod
    def _get_keyboard_indicators(sim_process: SimulatedProcess) -> List[str]:
        """Get keyboard-related indicators for a simulated process."""
        if not sim_process.keyboard_related:
            return []

        return [
            "Process name contains input-related keywords",
            "May be accessing keyboard devices (simulated)",
            "Detected patterns matching keyboard logger behavior",
        ]

    @staticmethod
    def _get_recommendations(level: RiskLevel) -> List[str]:
        """Get recommendations for a risk level."""
        recommendations = {
            RiskLevel.CRITICAL: [
                "🔴 CRITICAL RISK: Immediate action recommended",
                "Consider blocking or terminating this process",
                "Add to blocklist to prevent future execution",
            ],
            RiskLevel.HIGH: [
                "🟠 HIGH RISK: Close monitoring recommended",
                "Consider blocking if behavior continues",
            ],
            RiskLevel.MEDIUM: [
                "🟡 MEDIUM RISK: Monitor this process",
            ],
            RiskLevel.LOW: [
                "✅ LOW RISK: Process appears safe",
            ],
        }
        return recommendations.get(level, [])


class DemoDataGenerator:
    """Generates demo data for initial UI population."""

    @staticmethod
    def get_sample_alerts() -> List[dict]:
        """Get sample alerts for demo."""
        return [
            {
                'process_name': 'keylogger.exe',
                'risk_level': 'CRITICAL',
                'risk_score': 95,
                'title': '🔴 INPUT DEVICE ACCESS: keylogger.exe',
                'description': 'Process may be accessing keyboard/input devices',
                'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(),
            },
            {
                'process_name': 'inputdevice.exe',
                'risk_level': 'CRITICAL',
                'risk_score': 88,
                'title': 'Critical Risk: inputdevice.exe',
                'description': 'Attempts to access input device interfaces',
                'timestamp': (datetime.now() - timedelta(minutes=12)).isoformat(),
            },
            {
                'process_name': 'logger_service.exe',
                'risk_level': 'HIGH',
                'risk_score': 72,
                'title': 'High Risk: logger_service.exe',
                'description': 'Logs user activities',
                'timestamp': (datetime.now() - timedelta(minutes=45)).isoformat(),
            },
        ]

    @staticmethod
    def get_sample_process_stats() -> dict:
        """Get sample process statistics for demo."""
        return {
            'total_processes': 247,
            'critical_risk': 2,
            'high_risk': 5,
            'medium_risk': 12,
            'low_risk': 228,
            'blocked': 3,
            'trusted': 15,
        }
