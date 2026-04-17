"""
Platform adapter factory for selecting OS-specific implementation.

This module provides a factory function that returns the correct
PlatformAdapter implementation for the running OS.
"""

import sys
from typing import Optional

from .base import PlatformAdapter
from .windows_adapter import WindowsAdapter
from .linux_adapter import LinuxAdapter
from .mac_adapter import MacOSAdapter


def get_platform_adapter() -> PlatformAdapter:
    """
    Get the appropriate platform adapter for the running OS.
    
    Returns:
        PlatformAdapter instance for the current platform
        
    Raises:
        RuntimeError: If running on unsupported platform
    """
    platform = sys.platform.lower()

    if platform == 'win32':
        return WindowsAdapter()
    elif platform.startswith('linux'):
        return LinuxAdapter()
    elif platform == 'darwin':  # macOS
        return MacOSAdapter()
    else:
        raise RuntimeError(f"Unsupported platform: {platform}")


def get_adapter_for_platform(platform_str: str) -> Optional[PlatformAdapter]:
    """
    Get adapter for a specific platform string.
    
    Args:
        platform_str: Platform identifier ('win32', 'linux', 'darwin')
        
    Returns:
        PlatformAdapter instance or None if unsupported
    """
    platform_lower = platform_str.lower()

    if platform_lower == 'win32' or platform_lower == 'windows':
        return WindowsAdapter()
    elif platform_lower == 'linux':
        return LinuxAdapter()
    elif platform_lower == 'darwin' or platform_lower == 'macos':
        return MacOSAdapter()

    return None
