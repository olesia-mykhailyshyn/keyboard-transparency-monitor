"""
Linux platform adapter for process control and monitoring.

This adapter provides:
- Process termination via signals
- Handle enumeration via /proc filesystem
- Limited keyboard detection (heuristic-based)
"""

import os
import signal
import subprocess
from typing import List, Optional, Dict
import psutil

from .base import PlatformAdapter, ProcessInfo


class LinuxAdapter(PlatformAdapter):
    """Linux implementation of platform adapter."""

    def get_platform_name(self) -> str:
        """Get platform name."""
        return 'Linux'

    def supports_keyboard_detection(self) -> bool:
        """Linux has limited keyboard detection without elevated privileges."""
        return False  # Limited support without kernel modules

    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process on Linux.
        
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
        Get number of open file descriptors for a process on Linux.
        
        Reads from /proc/[pid]/fd directory.
        """
        try:
            fd_path = f'/proc/{pid}/fd'
            if os.path.isdir(fd_path):
                # Count number of entries in fd directory
                fds = os.listdir(fd_path)
                return len(fds)
        except (OSError, PermissionError):
            pass

        return None

    def check_keyboard_access(self, pid: int) -> bool:
        """
        Check if a process is accessing input devices on Linux.
        
        Limited implementation: checks for event device access and command-line keywords.
        """
        indicators = self._detect_keyboard_indicators(pid)
        return len(indicators) > 0

    def _detect_keyboard_indicators(self, pid: int) -> List[str]:
        """
        Detect keyboard/input device access indicators for a process on Linux.
        
        Methods:
        1. Check opened files for /dev/input/* patterns
        2. Check command line for suspicious keywords
        3. Check process name
        
        Returns:
            List of detected indicators
        """
        indicators = []

        # Method 1: Check open files for input devices
        try:
            fd_path = f'/proc/{pid}/fd'
            if os.path.isdir(fd_path):
                for fd in os.listdir(fd_path):
                    try:
                        link = os.readlink(f'{fd_path}/{fd}')
                        if '/dev/input' in link:
                            indicators.append(f"Open handle to input device: {link}")
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass

        # Method 2: Check command line
        try:
            proc = psutil.Process(pid)
            cmdline = ' '.join(proc.cmdline()).lower()

            keywords = {'keyboard', 'input', 'keylog', 'keystroke', 'monitor', 'hook'}
            for keyword in keywords:
                if keyword in cmdline:
                    indicators.append(f"Keyword in cmdline: {keyword}")
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return indicators

    def is_elevated(self) -> bool:
        """Check if running as root."""
        return os.getuid() == 0 if hasattr(os, 'getuid') else False

    def request_elevation(self) -> bool:
        """
        Request root elevation on Linux.
        
        Returns False as this requires user interaction outside the app.
        """
        return False

    def get_system_info(self) -> Dict[str, str]:
        """Get Linux system information."""
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
            return {'platform': 'Linux (unknown)'}

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get Linux-specific process information."""
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
        """Get Linux capabilities."""
        return [
            'process_termination',
            'handle_count',
            'privilege_detection',
        ]
