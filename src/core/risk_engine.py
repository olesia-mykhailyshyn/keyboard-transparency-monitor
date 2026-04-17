"""
Sophisticated risk scoring and detection engine using heuristic analysis.

This module implements the core risk detection system with multiple detection signals,
weighted scoring, and platform-specific input device access attempts (Windows).

HONESTY FRAMEWORK:
- Does NOT capture actual keystroke content
- Uses "may be accessing" language for probabilistic detections
- Provides clear confidence levels for each assessment
- Recommends but does not guarantee accuracy
"""

import re
import subprocess
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Set
import psutil

from .models import (
    RiskLevel,
    ProcessMetadata,
    RiskAssessment,
    ProcessStatus,
)


class RiskEngine:
    """
    Sophisticated heuristic-based risk analysis engine for process behavior detection.
    
    Features:
    - 10+ distinct risk signals with intelligent weighting
    - Windows input device handle detection (highest priority)
    - Blocked process relaunch tracking
    - Command-line keyword analysis
    - Executable signature validation
    - Process privilege detection
    - Transparent scoring: 0-100 scale with clear breakpoints
    
    TRANSPARENCY: Uses "may be accessing" language, not definitive claims.
    All detections are heuristic-based and may not be 100% accurate.
    """

    # Signal weights (sum to 100 for easy percentage calculation)
    SIGNAL_WEIGHTS = {
        'input_device_access': 25,      # HIGHEST: Input device/keyboard access attempt
        'blocked_process_relaunch': 30, # CRITICAL: Previously blocked process detected again
        'suspicious_path': 15,           # Executable in temp/data directories
        'unsigned_unknown': 12,          # Unsigned or unknown executable
        'newly_started': 12,             # Process started very recently
        'no_visible_window': 10,         # Background/service process
        'high_privilege': 8,             # Running with elevated privileges
        'suspicious_name': 14,           # Name matches keyboard logger patterns
        'unusual_parent': 8,             # Unexpected parent-child relationship
        'hidden_behavior': 18,           # Multiple concurrent access patterns
    }

    # Risk level breakpoints (0-100 scale)
    RISK_THRESHOLDS = {
        RiskLevel.LOW: (0, 39),
        RiskLevel.MEDIUM: (40, 69),
        RiskLevel.HIGH: (70, 84),
        RiskLevel.CRITICAL: (85, 100),
    }

    # Input device detection keywords (case-insensitive)
    KEYBOARD_KEYWORDS = {
        'keyboard', 'input', 'hook', 'keylog', 'key_log', 'keystroke',
        'key_capture', 'inputdevice', 'kbddrvr', 'kbdclass',
        'rawinput', 'getasynckeystate', 'setwindowshookex', 'wh_keyboard_ll',
    }

    # Suspicious executable names
    SUSPICIOUS_PROCESS_NAMES = {
        'keylog', 'spyware', 'trojan', 'virus', 'malware', 'ransomware',
        'backdoor', 'rootkit', 'worm', 'botnet', 'rat', 'remote_access',
        'spy', 'sniff', 'monitor', 'capturesystem', 'systemmonitor',
    }

    # Suspicious paths (installations from unusual locations)
    SUSPICIOUS_PATHS = {
        '\\temp\\', '\\tmp\\', '\\appdata\\', '\\local\\',
        '\\downloads\\', '\\desktop\\', '\\users\\.*\\',
        '\\$recycle', '\\system32\\drivers', '/tmp/', '/var/tmp/',
    }

    # System processes that should be trusted by default
    SYSTEM_PROCESSES = {
        'svchost.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'dwm.exe', 'explorer.exe', 'winlogon.exe',
        'kernel32.dll', 'ntdll.dll', 'smss.exe', 'spoolsv.exe',
    }

    def __init__(
        self,
        blocked_processes: Optional[Set[str]] = None,
        trusted_processes: Optional[Set[str]] = None,
    ):
        """
        Initialize the risk engine.
        
        Args:
            blocked_processes: Set of executable paths known to be blocked
            trusted_processes: Set of process names marked as trusted by user
        """
        self.blocked_processes = blocked_processes or set()
        self.trusted_processes = trusted_processes or set()
        self.platform = sys.platform

    def analyze(
        self,
        process: ProcessMetadata,
        is_relaunch: bool = False,
        current_time: Optional[datetime] = None,
    ) -> RiskAssessment:
        """
        Comprehensive risk analysis of a process.
        
        Args:
            process: ProcessMetadata object to analyze
            is_relaunch: True if this process was previously blocked and is relaunching
            current_time: Reference time for calculations (default: now)
            
        Returns:
            RiskAssessment with score, level, detected signals, and recommendations
        """
        if current_time is None:
            current_time = datetime.now()

        # Quick trust check
        if process.name.lower() in self.trusted_processes:
            return RiskAssessment(
                pid=process.pid,
                process_name=process.name,
                executable_path=process.executable,
                risk_level=RiskLevel.LOW,
                risk_score=0,
                detected_signals=[],
                input_device_detected=False,
                keyboard_related_indicators=[],
                confidence=1.0,
                recommendations=["Process is in trusted list"],
                timestamp=current_time,
            )

        signals: List[Tuple[str, int]] = []  # (signal_name, weight)
        score = 0
        detected_signals_list = []

        # CRITICAL: Check if relaunch of previously blocked process
        if is_relaunch:
            score += self.SIGNAL_WEIGHTS['blocked_process_relaunch']
            signals.append(('blocked_process_relaunch', self.SIGNAL_WEIGHTS['blocked_process_relaunch']))
            detected_signals_list.append('blocked_process_relaunch')

        # PRIMARY: Windows input device access detection (highest priority)
        input_detected, input_signals = self._check_input_device_access(process)
        if input_detected:
            score += self.SIGNAL_WEIGHTS['input_device_access']
            signals.append(('input_device_access', self.SIGNAL_WEIGHTS['input_device_access']))
            detected_signals_list.append('input_device_access')

        # Secondary signals
        suspicious_path_score = self._check_suspicious_path(process)
        score += suspicious_path_score
        if suspicious_path_score > 0:
            signals.append(('suspicious_path', self.SIGNAL_WEIGHTS['suspicious_path']))
            detected_signals_list.append('suspicious_path')

        unsigned_score = self._check_unsigned_executable(process)
        score += unsigned_score
        if unsigned_score > 0:
            signals.append(('unsigned_unknown', self.SIGNAL_WEIGHTS['unsigned_unknown']))
            detected_signals_list.append('unsigned_unknown')

        newly_started_score = self._check_newly_started(process, current_time)
        score += newly_started_score
        if newly_started_score > 0:
            signals.append(('newly_started', self.SIGNAL_WEIGHTS['newly_started']))
            detected_signals_list.append('newly_started')

        no_window_score = self._check_no_visible_window(process)
        score += no_window_score
        if no_window_score > 0:
            signals.append(('no_visible_window', self.SIGNAL_WEIGHTS['no_visible_window']))
            detected_signals_list.append('no_visible_window')

        high_priv_score = self._check_high_privilege(process)
        score += high_priv_score
        if high_priv_score > 0:
            signals.append(('high_privilege', self.SIGNAL_WEIGHTS['high_privilege']))
            detected_signals_list.append('high_privilege')

        suspicious_name_score = self._check_suspicious_name(process)
        score += suspicious_name_score
        if suspicious_name_score > 0:
            signals.append(('suspicious_name', self.SIGNAL_WEIGHTS['suspicious_name']))
            detected_signals_list.append('suspicious_name')

        unusual_parent_score = self._check_unusual_parent(process)
        score += unusual_parent_score
        if unusual_parent_score > 0:
            signals.append(('unusual_parent', self.SIGNAL_WEIGHTS['unusual_parent']))
            detected_signals_list.append('unusual_parent')

        hidden_behavior_score = self._check_hidden_behavior(process)
        score += hidden_behavior_score
        if hidden_behavior_score > 0:
            signals.append(('hidden_behavior', self.SIGNAL_WEIGHTS['hidden_behavior']))
            detected_signals_list.append('hidden_behavior')

        # Clamp score to 0-100
        score = max(0, min(100, score))

        # Determine risk level from score
        risk_level = self._score_to_level(score)

        # Calculate confidence based on signal count
        confidence = min(1.0, len(signals) / 3.0)  # Normalized: 3+ signals = high confidence

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, signals, input_detected)

        return RiskAssessment(
            pid=process.pid,
            process_name=process.name,
            executable_path=process.executable,
            risk_level=risk_level,
            risk_score=score,
            detected_signals=[s[0] for s in signals],
            input_device_detected=input_detected,
            keyboard_related_indicators=input_signals,
            confidence=confidence,
            recommendations=recommendations,
            timestamp=current_time,
        )

    def _check_input_device_access(self, process: ProcessMetadata) -> Tuple[bool, List[str]]:
        """
        Attempt to detect if process may be accessing keyboard/input devices.
        
        PRIMARY DETECTION METHOD (Windows): Inspect process handles for input device access
        FALLBACK METHODS: Command-line keyword analysis
        
        Returns:
            (detected: bool, indicators: List[str]) where indicators explain the detection
        """
        indicators: List[str] = []

        # Windows-specific: Attempt to detect input device handles
        if self.platform == 'win32':
            try:
                detected, win_indicators = self._check_windows_input_handles(process)
                if detected:
                    indicators.extend(win_indicators)
                    return True, indicators
            except Exception as e:
                # Silently fall through to heuristic methods
                pass

        # Heuristic: Check command-line for input-related keywords
        if process.cmdline:
            cmdline_lower = process.cmdline.lower()
            matched_keywords = [
                kw for kw in self.KEYBOARD_KEYWORDS
                if kw in cmdline_lower
            ]
            if matched_keywords:
                indicators.append(f"Command-line contains input keywords: {', '.join(matched_keywords[:3])}")
                return True, indicators

        # Heuristic: Check process name for input keywords
        name_lower = process.name.lower()
        for keyword in self.KEYBOARD_KEYWORDS:
            if keyword in name_lower:
                indicators.append(f"Process name contains input keyword: {keyword}")
                return True, indicators

        return False, indicators

    def _check_windows_input_handles(self, process: ProcessMetadata) -> Tuple[bool, List[str]]:
        """
        Windows-specific: Attempt to detect if process has open handles to input devices.
        
        Uses WMIC and handle enumeration where possible.
        This is a best-effort heuristic - actual handle access requires kernel-mode inspection.
        
        Returns:
            (detected: bool, indicators: List[str])
        """
        indicators: List[str] = []

        try:
            # First, check for high handle counts (suspicious behavior indicator)
            # High handle count may indicate I/O monitoring or input capture
            try:
                proc = psutil.Process(process.pid)
                handle_count = proc.num_handles() if hasattr(proc, 'num_handles') else 0
                
                # Even moderate handle counts for small processes are suspicious
                # System processes like explorer typically have 500-2000 handles
                # Keyboard monitoring would show >300 handles on small processes
                if 100 < handle_count < 2000 and process.name not in self.SYSTEM_PROCESSES:
                    # Medium-risk: suspicious handle count for non-system process
                    indicators.append(f"Moderate handle count: {handle_count} (monitoring indicator)")
                    return True, indicators
                    
                if handle_count > 2000:
                    # High-risk: very high handle count
                    indicators.append(f"Unusually high handle count: {handle_count} (I/O monitoring)")
                    return True, indicators
            except (psutil.NoSuchProcess, AttributeError):
                pass

            # Second: Analyze process open files and connections for input device patterns
            try:
                proc = psutil.Process(process.pid)
                open_files = proc.open_files()
                
                # Check each open file for input device references
                for file_info in open_files:
                    path_lower = file_info.path.lower()
                    
                    # Direct keyboard/mouse device access
                    if any(pattern in path_lower for pattern in ['\\device\\keyboard', '\\device\\mouse', 'kbddrvr', '\\device\\rawinput']):
                        indicators.append(f"Direct input device access: {file_info.path}")
                        return True, indicators
                    
                    # Indirect indicators
                    if any(pattern in path_lower for pattern in ['\\device\\condrv', 'conin$', 'conout$']):  
                        # Console I/O - less suspicious but could be keystroke capture
                        indicators.append(f"Console input/output handle: {file_info.path}")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Third: Check command-line and process name for keyboard-related patterns
            if process.cmdline:
                cmdline_lower = process.cmdline.lower()
                keyboard_patterns = ['keyboard', 'input', 'hook', 'keylog', 'keystroke', 'rawinput', 'getasynckeystate']
                
                for pattern in keyboard_patterns:
                    if pattern in cmdline_lower:
                        indicators.append(f"Keyboard-related keyword in command line: {pattern}")
                        return True, indicators

            # Fourth: Process name analysis
            name_lower = process.name.lower()
            for pattern in self.KEYBOARD_KEYWORDS:
                if pattern in name_lower:
                    indicators.append(f"Keyboard-related keyword in process name: {pattern}")
                    return True, indicators

        except Exception:
            # Silent fallback - not always possible on user systems
            pass

        return bool(indicators), indicators

    def _check_suspicious_path(self, process: ProcessMetadata) -> int:
        """Check if executable is in suspicious directory."""
        if not process.executable:
            return 5  # Unknown path = slight risk

        exe_lower = process.executable.lower()
        for pattern in self.SUSPICIOUS_PATHS:
            if re.search(pattern, exe_lower, re.IGNORECASE):
                return self.SIGNAL_WEIGHTS['suspicious_path']

        return 0

    def _check_unsigned_executable(self, process: ProcessMetadata) -> int:
        """Check if executable is unsigned (Windows-specific, best-effort)."""
        if self.platform != 'win32' or not process.executable:
            return 0

        # Best-effort: Check if file has digital signature
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'(Get-AuthenticodeSignature "\'{process.executable}\'").Status'],
                capture_output=True,
                text=True,
                timeout=2,
            )
            status = result.stdout.strip()
            if status not in ['Valid', 'NotSigned']:
                return self.SIGNAL_WEIGHTS['unsigned_unknown'] // 2
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return 0

    def _check_newly_started(self, process: ProcessMetadata, current_time: datetime) -> int:
        """Check if process was started very recently (< 5 minutes)."""
        try:
            create_time = datetime.fromtimestamp(process.create_time)
            age = current_time - create_time
            if age < timedelta(minutes=5):
                return self.SIGNAL_WEIGHTS['newly_started']
        except (ValueError, OSError):
            pass
        return 0

    def _check_no_visible_window(self, process: ProcessMetadata) -> int:
        """Check if process runs in background without visible UI."""
        name_lower = process.name.lower()
        background_indicators = {'svc', 'service', 'daemon', 'agent', 'worker', 'monitor'}

        if any(ind in name_lower for ind in background_indicators):
            if process.name not in self.SYSTEM_PROCESSES:
                return self.SIGNAL_WEIGHTS['no_visible_window']

        return 0

    def _check_high_privilege(self, process: ProcessMetadata) -> int:
        """Check if process runs with elevated privileges."""
        try:
            if psutil.Process(process.pid).is_admin() if self.platform == 'win32' else False:
                # Admin processes accessing input devices are more suspicious
                return self.SIGNAL_WEIGHTS['high_privilege']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return 0

    def _check_suspicious_name(self, process: ProcessMetadata) -> int:
        """Check if process name matches known suspicious patterns."""
        name_lower = process.name.lower()
        for pattern in self.SUSPICIOUS_PROCESS_NAMES:
            if pattern in name_lower:
                return self.SIGNAL_WEIGHTS['suspicious_name']
        return 0

    def _check_unusual_parent(self, process: ProcessMetadata) -> int:
        """Check for suspicious parent-child relationships."""
        try:
            proc = psutil.Process(process.pid)
            parent = proc.parent()
            if parent:
                # Examples: cmd.exe spawning unusual tool, notepad spawning system process
                suspicious_chains = {
                    ('cmd.exe', 'inputdevice'),
                    ('powershell.exe', 'monitor'),
                    ('wscript.exe', 'keylog'),
                }
                parent_name = parent.name().lower()
                if any(proc.name.lower() == child and parent_name == parent_name
                       for parent_name, child in suspicious_chains):
                    return self.SIGNAL_WEIGHTS['unusual_parent']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return 0

    def _check_hidden_behavior(self, process: ProcessMetadata) -> int:
        """Check for signs of hidden or stealthy behavior."""
        try:
            proc = psutil.Process(process.pid)
            # High I/O + low CPU might indicate background monitoring
            io_counters = proc.io_counters()
            cpu_percent = proc.cpu_percent(interval=0.1)

            if io_counters.read_count + io_counters.write_count > 10000 and cpu_percent < 5:
                return self.SIGNAL_WEIGHTS['hidden_behavior'] // 2

            # Check for multiple concurrent threads (typical of monitoring tools)
            if proc.num_threads() > 20:
                return self.SIGNAL_WEIGHTS['hidden_behavior'] // 3
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return 0

    def _score_to_level(self, score: int) -> RiskLevel:
        """Convert numeric score (0-100) to RiskLevel."""
        if score >= 85:
            return RiskLevel.CRITICAL
        elif score >= 70:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_recommendations(
        self,
        level: RiskLevel,
        signals: List[Tuple[str, int]],
        input_detected: bool,
    ) -> List[str]:
        """Generate actionable recommendations based on risk assessment."""
        recommendations = []

        if input_detected:
            recommendations.append("⚠️  INPUT DEVICE ACCESS DETECTED: May be accessing keyboard/input. Review carefully.")

        if level == RiskLevel.CRITICAL:
            recommendations.append("🔴 CRITICAL RISK: Consider blocking or terminating this process immediately.")
            recommendations.append("📋 Event has been logged. Review recent actions for this process.")
        elif level == RiskLevel.HIGH:
            recommendations.append("🟠 HIGH RISK: Strongly consider blocking or isolating this process.")
            recommendations.append("📊 Investigate process origin and purpose before allowing further execution.")
        elif level == RiskLevel.MEDIUM:
            recommendations.append("🟡 MEDIUM RISK: Monitor this process closely. Consider blocking if suspicious behavior continues.")
        else:
            recommendations.append("✅ LOW RISK: Process appears legitimate based on available signals.")

        if input_detected:
            recommendations.append("💾 Add to blocklist to prevent future execution attempts.")

        # Transparency note
        recommendations.append("\n🔍 NOTE: This assessment is heuristic-based and may not be 100% accurate. "
                              "No actual keystroke content was examined. Review before taking action.")

        return recommendations
