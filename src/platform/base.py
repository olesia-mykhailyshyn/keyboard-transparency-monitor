"""
Base platform adapter class providing abstract interface for OS-specific operations.

This module defines the contract that all platform-specific adapters must implement.
Adapters handle:
- Process termination (with privilege elevation if needed)
- Input device detection (Windows) or fallbacks
- Handle enumeration and inspection
- System information collection
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict
from dataclasses import dataclass


@dataclass
class ProcessInfo:
    """Basic process information from OS."""
    pid: int
    name: str
    executable: Optional[str] = None
    handle_count: int = 0
    owned_by_admin: bool = False


class PlatformAdapter(ABC):
    """
    Abstract base class for platform-specific operations.
    
    Each platform (Windows, Linux, macOS) implements specific methods
    for process control, device detection, and system integration.
    """

    @abstractmethod
    def get_platform_name(self) -> str:
        """
        Get the name of the platform.
        
        Returns:
            Platform name (e.g., 'Windows', 'Linux', 'Darwin')
        """
        pass

    @abstractmethod
    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process by PID.
        
        Args:
            pid: Process ID to terminate
            force: If True, use forceful termination (SIGKILL on Unix, TerminateProcess on Windows)
            
        Returns:
            True if termination succeeded or process not found, False if permission denied
        """
        pass

    @abstractmethod
    def get_process_handle_count(self, pid: int) -> Optional[int]:
        """
        Get the number of open handles for a process.
        
        Args:
            pid: Process ID
            
        Returns:
            Handle count or None if unable to determine
        """
        pass

    @abstractmethod
    def check_keyboard_access(self, pid: int) -> bool:
        """
        Check if a process appears to be accessing keyboard/input devices.
        
        Args:
            pid: Process ID to check
            
        Returns:
            True if process appears to have keyboard access attempts detected
        """
        pass

    @abstractmethod
    def is_elevated(self) -> bool:
        """
        Check if the monitoring application is running with elevated privileges.
        
        Returns:
            True if running as admin/root, False otherwise
        """
        pass

    @abstractmethod
    def get_system_info(self) -> Dict[str, str]:
        """
        Get system information relevant to monitoring.
        
        Returns:
            Dict with OS version, architecture, etc.
        """
        pass

    @abstractmethod
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Get basic platform-specific process information.
        
        Args:
            pid: Process ID
            
        Returns:
            ProcessInfo object or None if unable to get info
        """
        pass

    @abstractmethod
    def request_elevation(self) -> bool:
        """
        Request elevated privileges if not already running as admin/root.
        
        Returns:
            True if elevated privileges are now available
        """
        pass

    def supports_keyboard_detection(self) -> bool:
        """
        Check if this platform supports direct keyboard device detection.
        
        Returns:
            True if platform supports native keyboard/input detection
        """
        return False  # Override in platform-specific implementations

    def get_capabilities(self) -> List[str]:
        """
        Get list of supported capabilities for this platform.
        
        Returns:
            List of capability strings (e.g., ['keyboard_detection', 'handle_enumeration'])
        """
        capabilities = ['process_termination', 'handle_count']
        
        if self.supports_keyboard_detection():
            capabilities.append('keyboard_detection')
        
        return capabilities
