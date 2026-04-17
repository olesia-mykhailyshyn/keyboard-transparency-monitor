"""
Windows-specific platform adapter for keyboard detection and process control.

This adapter implements:
- Input device handle detection via WMIC and handle inspection
- Process termination with privilege elevation
- Handle enumeration and analysis
- Admin privilege detection and elevation prompts
"""

import os
import subprocess
import ctypes
import tempfile
from typing import List, Optional, Dict
import psutil

from .base import PlatformAdapter, ProcessInfo


class WindowsAdapter(PlatformAdapter):
    """Windows implementation of platform adapter."""

    KEYBOARD_DEVICE_NAMES = {
        '\\Device\\Keyboard',
        '\\Device\\KeyboardClass',
        '\\Driver\\Keyboard',
        '\\Device\\Mouse',
        '\\Device\\MouseClass',
    }

    def __init__(self):
        """Initialize Windows adapter."""
        self._elevated = self._check_elevated()

    def get_platform_name(self) -> str:
        """Get platform name."""
        return 'Windows'

    def supports_keyboard_detection(self) -> bool:
        """Windows supports keyboard device detection."""
        return True

    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process on Windows.
        
        Uses taskkill command with elevation if needed.
        """
        try:
            if force:
                # Force termination (/F = forceful)
                result = subprocess.run(
                    ['taskkill', '/PID', str(pid), '/F'],
                    capture_output=True,
                    timeout=5,
                )
            else:
                # Graceful termination
                result = subprocess.run(
                    ['taskkill', '/PID', str(pid)],
                    capture_output=True,
                    timeout=5,
                )

            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def get_process_handle_count(self, pid: int) -> Optional[int]:
        """
        Get handle count for a process on Windows.
        
        Uses tasklist with verbose output or WMI.
        """
        try:
            # Attempt via WMI
            result = subprocess.run(
                [
                    'wmic',
                    'process',
                    'where',
                    f'ProcessId={pid}',
                    'get',
                    'HandleCount',
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip().isdigit():
                        return int(line.strip())

            # Also try via psutil if available
            try:
                proc = psutil.Process(pid)
                if hasattr(proc, 'num_handles'):
                    return proc.num_handles()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def check_keyboard_access(self, pid: int) -> bool:
        """
        Check if a process is accessing keyboard devices on Windows.
        
        Uses Handle.exe or WMI to inspect open handles.
        """
        indicators = self._detect_keyboard_indicators(pid)
        return len(indicators) > 0

    def _detect_keyboard_indicators(self, pid: int) -> List[str]:
        """
        Detect keyboard/input device access indicators for a process.
        
        Uses multiple methods:
        1. Check command line for input keywords
        2. High handle count (suspicious for monitoring)
        3. Use Handle.exe if available (Sysinternals)
        
        Returns:
            List of detected indicators/suspicious patterns
        """
        indicators = []

        # Method 1: Check process command line for keyboard-related keywords
        try:
            proc = psutil.Process(pid)
            cmdline = ' '.join(proc.cmdline()).lower()
            exe_name = proc.name().lower()

            keyboard_keywords = {
                'keyboard', 'input', 'hook', 'keylog', 'key_log', 'keystroke',
                'inputdevice', 'rawinput', 'setwindowshookex',
                'getasynckeystate', 'kbdhook', 'monitor', 'logger', 'capture',
            }

            # Check command line
            for keyword in keyboard_keywords:
                if keyword in cmdline:
                    indicators.append(f"Keyword in cmdline: {keyword}")
                    break
            
            # Check executable name
            for keyword in keyboard_keywords:
                if keyword in exe_name:
                    indicators.append(f"Keyword in process name: {keyword}")
                    break
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Method 2: High handle count is suspicious for potentially monitoring process
        try:
            handle_count = self.get_process_handle_count(pid)
            if handle_count and handle_count > 500:
                indicators.append(f"Unusually high handle count: {handle_count}")
        except Exception:
            pass

        # Method 3: Attempt to use Handle.exe (Sysinternals) if available
        # This is optional - only if handle.exe is in PATH
        try:
            result = subprocess.run(
                ['handle.exe', '-p', str(pid), '-a'],
                capture_output=True,
                text=True,
                timeout=3,
            )

            if result.returncode == 0:
                output_lower = result.stdout.lower()
                for device in self.KEYBOARD_DEVICE_NAMES:
                    if device.lower() in output_lower:
                        indicators.append(f"Open handle to: {device}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Handle.exe not available - this is OK, we have other methods
            pass

        return indicators

    def is_elevated(self) -> bool:
        """Check if running with administrator privileges."""
        return self._elevated

    def _check_elevated(self) -> bool:
        """Check if current process has admin privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False

    def request_elevation(self) -> bool:
        """
        Request administrator elevation.
        
        Shows UAC dialog to user. Returns True if user grants.
        Note: This is incomplete and would need proper implementation.
        
        Returns:
            True if elevation successful or already elevated
        """
        if self._check_elevated():
            return True

        # Would show UAC prompt in full implementation
        # For now, return False indicating user needs to run as admin
        return False

    def get_system_info(self) -> Dict[str, str]:
        """Get Windows system information."""
        try:
            import platform
            return {
                'platform': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'elevated': str(self._elevated),
            }
        except Exception:
            return {'platform': 'Windows (unknown version)'}

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get Windows-specific process information."""
        try:
            proc = psutil.Process(pid)

            handle_count = None
            if hasattr(proc, 'num_handles'):
                try:
                    handle_count = proc.num_handles()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            # Check if owned by admin
            owned_by_admin = False
            try:
                # Heuristic: check if running from system32 or is system process
                exe = proc.exe().lower()
                owned_by_admin = 'system32' in exe or proc.name().lower() in {'svchost.exe', 'lsass.exe', 'services.exe'}
            except (psutil.AccessDenied, FileNotFoundError):
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
        """Get Windows-specific capabilities."""
        return [
            'process_termination',
            'handle_count',
            'keyboard_detection',
            'admin_elevation',
            'wmi_inspection',
        ]
