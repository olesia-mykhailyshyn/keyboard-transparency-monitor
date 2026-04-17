"""
Main monitoring service that orchestrates process scanning, risk analysis, and alerts.

This is the core engine that:
- Continuously scans running processes
- Runs risk analysis on each process
- Detects relaunches of blocked processes
- Generates alerts
- Coordinates with all other services
"""

import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Callable
import psutil

from .models import ProcessMetadata, RiskLevel, RiskAssessment
from .process_scanner import ProcessScanner
from .risk_engine import RiskEngine
from .blocklist_service import BlocklistService
from .trust_service import TrustService
from .alert_manager import AlertManager
from .user_action_logger import UserActionLogger


class MonitorService:
    """
    Main monitoring service that continuously monitors running processes.
    
    This service:
    - Scans all running processes at regular intervals
    - Analyzes each process for keyboard/input access risks
    - Tracks blocklist and trustlist
    - Generates alerts for suspicious activity
    - Detects relaunches of blocked processes
    """

    # Default scan interval in seconds
    DEFAULT_SCAN_INTERVAL = 5  # Every 5 seconds

    def __init__(
        self,
        process_scanner: ProcessScanner,
        risk_engine: RiskEngine,
        blocklist_service: BlocklistService,
        trust_service: TrustService,
        alert_manager: AlertManager,
        action_logger: UserActionLogger,
        scan_interval: float = DEFAULT_SCAN_INTERVAL,
    ):
        """
        Initialize monitor service.
        
        Args:
            process_scanner: ProcessScanner instance
            risk_engine: RiskEngine instance
            blocklist_service: BlocklistService instance
            trust_service: TrustService instance
            alert_manager: AlertManager instance
            action_logger: UserActionLogger instance
            scan_interval: Seconds between scans (default: 5)
        """
        self.scanner = process_scanner
        self.risk_engine = risk_engine
        self.blocklist_service = blocklist_service
        self.trust_service = trust_service
        self.alerts = alert_manager
        self.actions = action_logger
        self.scan_interval = scan_interval

        # Threading
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._paused = False
        self._lock = threading.Lock()

        # Session state
        self._seen_processes: Dict[int, ProcessMetadata] = {}
        self._last_scan_time: Optional[datetime] = None
        self._scan_count = 0
        self._last_scan_duration = 0.0
        self._scan_errors = 0

        # Statistics
        self._processes_analyzed = 0
        self._alerts_generated = 0
        self._blocked_processes_detected = 0
        self._relaunches_detected = 0

        # Callbacks
        self._on_process_detected: List[Callable] = []
        self._on_alert_generated: List[Callable] = []
        self._on_blocked_relaunch: List[Callable] = []

    def start(self) -> bool:
        """
        Start the monitoring service.
        
        Returns:
            True if successfully started
        """
        with self._lock:
            if self._running:
                return False

            self._running = True
            self._paused = False
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()

            return True

    def stop(self) -> bool:
        """
        Stop the monitoring service gracefully.
        
        Returns:
            True if successfully stopped
        """
        with self._lock:
            if not self._running:
                return False

            self._running = False

        # Wait for thread to exit
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

        return True

    def pause(self):
        """Temporarily pause monitoring without stopping."""
        self._paused = True

    def resume(self):
        """Resume monitoring if paused."""
        self._paused = False

    def is_running(self) -> bool:
        """Check if monitor is currently running."""
        return self._running

    def is_paused(self) -> bool:
        """Check if monitor is paused."""
        return self._paused

    def register_on_process_detected(self, callback: Callable):
        """Register callback for when process is detected."""
        if callback and callable(callback):
            self._on_process_detected.append(callback)

    def register_on_alert_generated(self, callback: Callable):
        """Register callback for when alert is generated."""
        if callback and callable(callback):
            self._on_alert_generated.append(callback)

    def register_on_blocked_relaunch(self, callback: Callable):
        """Register callback for when blocked process relaunches."""
        if callback and callable(callback):
            self._on_blocked_relaunch.append(callback)

    def _monitor_loop(self):
        """Main monitoring loop that runs in background thread."""
        while self._running:
            try:
                if not self._paused:
                    self._perform_scan()

                time.sleep(self.scan_interval)

            except Exception as e:
                self._scan_errors += 1
                # Log error but don't crash
                time.sleep(1)

    def _perform_scan(self):
        """
        Perform a single scan cycle.
        
        This:
        1. Scans all running processes
        2. Checks against blocklist and trustlist
        3. Runs risk analysis on suspicious processes
        4. Detects relaunches
        5. Generates alerts as needed
        """
        scan_start = datetime.now()

        try:
            # 1. Scan all running processes
            processes = self.scanner.scan_all_processes()
            current_pids = {p.pid for p in processes}
            
            # DEBUG
            print(f"[MonitorService] Scanned {len(processes)} processes")

            # Check for processes that exited
            exited_pids = set(self._seen_processes.keys()) - current_pids
            for pid in exited_pids:
                del self._seen_processes[pid]

            # 2. Analyze each process
            analyzed = 0
            for process in processes:
                self._process_analyzed(process)
                analyzed += 1
            
            print(f"[MonitorService] Analyzed {analyzed} processes")

            self._last_scan_time = datetime.now()
            self._last_scan_duration = (self._last_scan_time - scan_start).total_seconds()
            self._scan_count += 1

        except Exception as e:
            print(f"[MonitorService] Scan error: {e}")
            self._scan_errors += 1

    def _process_analyzed(self, process: ProcessMetadata):
        """
        Analyze a single process for risk.
        
        Args:
            process: ProcessMetadata to analyze
        """
        self._processes_analyzed += 1

        # 1. Check if process is trusted
        if self.trust_service.is_trusted(process.executable or process.name):
            self._seen_processes[process.pid] = process
            return

        # 2. Check if process is blocked
        is_blocked = self.blocklist_service.is_blocked(process.executable or process.name)

        # 3. Detect relaunch of blocked process
        if is_blocked:
            attempt_count = self.blocklist_service.record_relaunch_attempt(
                executable_path=process.executable or process.name,
                pid=process.pid,
            )

            if attempt_count >= 1:  # Any relaunch attempt is suspicious
                self._relaunches_detected += 1

                # Generate critical alert
                alert = self.alerts.create_alert_from_assessment(
                    assessment=RiskAssessment(
                        pid=process.pid,
                        process_name=process.name,
                        executable_path=process.executable,
                        risk_level=RiskLevel.CRITICAL,
                        risk_score=100,
                        detected_signals=['blocked_process_relaunch'],
                        input_device_detected=False,
                        keyboard_related_indicators=[],
                        confidence=1.0,
                        recommendations=[
                            "🔴 CRITICAL: Previously blocked process detected.",
                            "Auto-terminating or blocking relaunch attempt.",
                        ],
                        timestamp=datetime.now(),
                    ),
                    process_name=process.name,
                    details=f"Relaunch attempt #{attempt_count}",
                )

                self._alerts_generated += 1

                # Invoke callbacks
                for callback in self._on_blocked_relaunch:
                    try:
                        callback(process, attempt_count)
                    except Exception:
                        pass

            return

        # 4. Run comprehensive risk analysis
        assessment = self.risk_engine.analyze(process, is_relaunch=False)

        # 5. ALWAYS invoke process detected callback - show ALL processes
        for callback in self._on_process_detected:
            try:
                print(f"[MonitorService] Invoking callback for {process.name} (PID {process.pid}), risk={assessment.risk_score}")
                callback(process, assessment)
            except Exception as e:
                print(f"[MonitorService] Callback error: {e}")
                pass

        # 6. Decide if alert is needed (high risk only)
        should_alert = assessment.risk_score >= 70

        # 7. Generate alert if needed
        if should_alert:
            alert = self.alerts.create_alert_from_assessment(
                assessment=assessment,
                process_name=process.name,
                details=f"Risk score: {assessment.risk_score}",
            )

            self._alerts_generated += 1
            self._blocked_processes_detected += 1

            # Invoke callbacks
            for callback in self._on_alert_generated:
                try:
                    callback(process, assessment, alert)
                except Exception:
                    pass

        # 8. Store in seen processes
        self._seen_processes[process.pid] = process

    def register_on_process_detected(self, callback: Callable):
        """
        Register callback for each process detected.
        
        Callback signature: callback(process: ProcessMetadata, assessment: RiskAssessment)
        """
        self._on_process_detected.append(callback)

    def register_on_alert_generated(self, callback: Callable):
        """
        Register callback for alerts.
        
        Callback signature: callback(process: ProcessMetadata, assessment: RiskAssessment, alert: Alert)
        """
        self._on_alert_generated.append(callback)

    def register_on_blocked_relaunch(self, callback: Callable):
        """
        Register callback for blocked process relaunches.
        
        Callback signature: callback(process: ProcessMetadata, attempt_count: int)
        """
        self._on_blocked_relaunch.append(callback)

    def get_statistics(self) -> Dict:
        """
        Get monitoring statistics.
        
        Returns:
            Dict with stats: processes_analyzed, alerts_generated, etc.
        """
        return {
            'running': self._running,
            'paused': self._paused,
            'scan_count': self._scan_count,
            'last_scan_time': self._last_scan_time.isoformat() if self._last_scan_time else None,
            'last_scan_duration_s': self._last_scan_duration,
            'scan_errors': self._scan_errors,
            'processes_analyzed': self._processes_analyzed,
            'alerts_generated': self._alerts_generated,
            'blocked_processes_detected': self._blocked_processes_detected,
            'relaunches_detected': self._relaunches_detected,
            'currently_tracked': len(self._seen_processes),
        }

    def force_scan(self) -> Dict:
        """
        Force an immediate scan (useful for testing or manual refresh).
        
        Returns:
            Statistics from the scan
        """
        if not self._running:
            self._perform_scan()

        return self.get_statistics()

    def start(self) -> None:
        """Start background monitoring."""
        if self.is_running:
            return

        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background monitoring."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=5.0)

    def set_scan_interval(self, interval: float) -> None:
        """Set scan interval in seconds."""
        self.scan_interval = max(2.0, min(300.0, interval))

    def _monitor_loop(self) -> None:
        """Main monitoring loop running in background thread."""
        while self.is_running:
            try:
                self._perform_scan()
            except Exception as e:
                print(f"Error in monitor loop: {e}")

            # Sleep in small intervals to allow quick shutdown
            for _ in range(int(self.scan_interval * 10)):
                if not self.is_running:
                    break
                time.sleep(0.1)

    def _perform_scan(self) -> None:
        """Run a single scan and analyze all processes."""
        processes = self.scanner.scan_all_processes()
        current_time = datetime.now()

        flagged_analyses: List[RiskAnalysis] = []

        for process in processes:
            analysis = self.risk_engine.analyze(process, current_time)

            # Only report flagged (non-LOW risk) processes
            if analysis.risk_level.value != 'LOW':
                flagged_analyses.append(analysis)

        # Notify all registered callbacks
        if flagged_analyses:
            with self._lock:
                for callback in self._callbacks:
                    try:
                        callback(flagged_analyses)
                    except Exception as e:
                        print(f"Error calling detection callback: {e}")

    def scan_now(self) -> List[RiskAssessment]:
        """
        Perform an immediate scan and return results.
        Does not affect background scan interval.
        
        Returns:
            List of RiskAssessment for flagged processes
        """
        processes = self.scanner.scan_all_processes()
        current_time = datetime.now()

        flagged = []
        for process in processes:
            analysis = self.risk_engine.analyze(process, current_time)
            if analysis.risk_level.value != 'LOW':
                flagged.append(analysis)

        return flagged
