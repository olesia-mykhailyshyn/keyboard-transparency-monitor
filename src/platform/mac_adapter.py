"""
macOS platform adapter for process control and monitoring.

This adapter provides:
- Process termination
- Handle enumeration via lsof
- Limited keyboard detection (heuristic-based)
"""

import os
import signal
import subprocess
from typing import List, Optional, Dict
import psutil

from .base import PlatformAdapter, ProcessInfo


class MacOSAdapter(PlatformAdapter):
    """macOS implementation of platform adapter."""

    def get_platform_name(self) -> str:
        """Get platform name."""
        return 'macOS'

    def supports_keyboard_detection(self) -> bool:
        """macOS keyboard detection requires accessibility permissions."""
        return False  # Limited support without system-level APIs

    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process on macOS.
        
        Uses SIGTERM (graceful) or SIGKILL (forceful).
        """
        try:
            if force:
                signal_num = signal.SIGKILL
            else:
                signal_num = signal.SIGTERM

            os.kill(pid, signal_num)
            return True
        except (ProcessLookupError, PermissionError, OSError):
            return False

    def get_process_handle_count(self, pid: int) -> Optional[int]:
        """
        Get number of open file descriptors for a process on macOS.
        
        Uses lsof command.
        """
        try:
            result = subprocess.run(
                ['lsof', '-p', str(pid)],
                capture_output=True,
                text=True,
                timeout=3,
            )

            if result.returncode == 0:
                # Count number of lines (each represents an open file/descriptor)
                lines = result.stdout.strip().split('\n')
                return max(0, len(lines) - 1)  # Subtract header line

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def check_keyboard_access(self, pid: int) -> bool:
        """
        Check if a process is accessing input devices on macOS.
        
        Limited implementation: checks command-line and process name.
        """
        indicators = self._detect_keyboard_indicators(pid)
        return len(indicators) > 0

    def _detect_keyboard_indicators(self, pid: int) -> List[str]:
        """
        Detect keyboard/input device access indicators for a process on macOS.
        
        Methods:
        1. Check command line for suspicious keywords
        2. Check process name
        3. Check for IOKit device access via lsof
        
        Returns:
            List of detected indicators
        """
        indicators = []

        # Method 1: Check command line
        try:
            proc = psutil.Process(pid)
            cmdline = ' '.join(proc.cmdline()).lower()

            keywords = {'keyboard', 'input', 'keylog', 'keystroke', 'iokit'}
            for keyword in keywords:
                if keyword in cmdline:
                    indicators.append(f"Keyword in cmdline: {keyword}")
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Method 2: Check open file descriptors for IOKit references
        try:
            result = subprocess.run(
                ['lsof', '-p', str(pid)],
                capture_output=True,
                text=True,
                timeout=3,
            )

            if result.returncode == 0:
                output_lower = result.stdout.lower()
                if 'iokit' in output_lower or 'keyboard' in output_lower:
                    indicators.append("IOKit or input device reference in open files")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return indicators

    def is_elevated(self) -> bool:
        """Check if running as root."""
        return os.getuid() == 0 if hasattr(os, 'getuid') else False

    def request_elevation(self) -> bool:
        """
        Request root elevation on macOS.
        
        Returns False as this requires user interaction outside the app.
        """
        return False

    def get_system_info(self) -> Dict[str, str]:
        """Get macOS system information."""
        try:
            import platform
            return {
                'platform': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'elevated': str(self.is_elevated()),
            }
        except Exception:
            return {'platform': 'macOS (unknown)'}

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get macOS-specific process information."""
        try:
            proc = psutil.Process(pid)

            handle_count = self.get_process_handle_count(pid)

            # Check if privileged process
            owned_by_admin = False
            try:
                if hasattr(proc, 'uids'):
                    owned_by_admin = proc.uids().real == 0
            except (psutil.AccessDenied, AttributeError):
                pass

            return ProcessInfo(
                pid=pid,
                name=proc.name(),
                executable=proc.exe() if proc.exe() else None,
                handle_count=handle_count or 0,
                owned_by_admin=owned_by_admin,
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_capabilities(self) -> List[str]:
        """Get macOS capabilities."""
        return [
            'process_termination',
            'handle_count',
            'privilege_detection',
        ]
