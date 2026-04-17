"""Platform adapters for OS-specific operations."""

from .base import PlatformAdapter, ProcessInfo
from .windows_adapter import WindowsAdapter
from .linux_adapter import LinuxAdapter
from .mac_adapter import MacOSAdapter
from .adapter_factory import get_platform_adapter, get_adapter_for_platform

__all__ = [
    'PlatformAdapter',
    'ProcessInfo',
    'WindowsAdapter',
    'LinuxAdapter',
    'MacOSAdapter',
    'get_platform_adapter',
    'get_adapter_for_platform',
]
