"""
Trust list management service for managing trusted/whitelisted processes.

This service handles:
- Adding/removing processes from trust list
- Checking if a process is trusted
- Managing trust exceptions
- Recording trust-related events
"""

from datetime import datetime
from typing import Dict, List
from .models import TrustedProcess, ProcessStatus
from storage.repositories import TrustlistRepository


class TrustService:
    """Manages the trust list of known safe processes."""

    def __init__(self, repository: TrustlistRepository):
        """
        Initialize trust service.
        
        Args:
            repository: TrustlistRepository for persistent storage
        """
        self.repository = repository
        self._cache: Dict[str, TrustedProcess] = {}  # In-memory cache for performance

    def trust_process(
        self,
        executable_path: str,
        process_name: str,
        reason: str = "User marked as trusted",
    ) -> TrustedProcess:
        """
        Add a process to the trust list.
        
        Args:
            executable_path: Full path to executable
            process_name: Name of the process
            reason: Reason for trusting
            
        Returns:
            TrustedProcess record
        """
        trusted = TrustedProcess(
            executable_path=executable_path,
            process_name=process_name,
            status=ProcessStatus.TRUSTED,
            reason=reason,
            trusted_at=datetime.now(),
        )

        self.repository.add_trusted_process(trusted)
        self._cache[executable_path.lower()] = trusted

        return trusted

    def untrust_process(self, executable_path: str) -> bool:
        """
        Remove a process from the trust list.
        
        Args:
            executable_path: Path to executable to untrust
            
        Returns:
            True if removed successfully, False if not in trust list
        """
        success = self.repository.remove_trusted(executable_path)
        if success:
            self._cache.pop(executable_path.lower(), None)
        return success

    def is_trusted(self, executable_path: str) -> bool:
        """
        Check if a process is on the trust list.
        
        Args:
            executable_path: Path to check
            
        Returns:
            True if process is in trust list
        """
        path_lower = executable_path.lower()

        # Check cache first
        if path_lower in self._cache:
            return True

        # Check repository
        if self.repository.is_trusted(executable_path):
            # Populate cache
            try:
                trusted_list = self.repository.get_all_trusted()
                for proc in trusted_list:
                    self._cache[proc.executable_path.lower()] = proc
            except Exception:
                pass
            return True

        return False

    def get_all_trusted(self) -> List[TrustedProcess]:
        """
        Get all currently trusted processes.
        
        Returns:
            List of TrustedProcess records
        """
        return self.repository.get_all_trusted()

    def get_trusted_by_name(self, process_name: str) -> List[TrustedProcess]:
        """
        Get all trusted processes matching a name.
        
        Args:
            process_name: Process name to search for
            
        Returns:
            List of matching TrustedProcess records
        """
        all_trusted = self.get_all_trusted()
        name_lower = process_name.lower()
        return [p for p in all_trusted if name_lower in p.process_name.lower()]

    def add_system_defaults(self) -> int:
        """
        Add default system processes to trust list.
        
        These are widely-known safe Windows system processes.
        User can remove any of these if desired.
        
        Returns:
            Number of default processes added
        """
        default_processes = [
            ('explorer.exe', 'Windows File Explorer'),
            ('svchost.exe', 'Windows Service Host'),
            ('dwm.exe', 'Desktop Window Manager'),
            ('winlogon.exe', 'Windows Logon'),
            ('csrss.exe', 'Client/Server Runtime Subsystem'),
            ('taskhost.exe', 'Windows Task Host'),
            ('taskmgr.exe', 'Task Manager'),
            ('powershell.exe', 'Windows PowerShell'),
            ('cmd.exe', 'Windows Command Prompt'),
            ('notepad.exe', 'Notepad'),
            ('calc.exe', 'Calculator'),
            ('mspaint.exe', 'Microsoft Paint'),
            ('wmplayer.exe', 'Windows Media Player'),
            ('chrome.exe', 'Google Chrome'),
            ('firefox.exe', 'Mozilla Firefox'),
            ('msedge.exe', 'Microsoft Edge'),
        ]

        count = 0
        for exe_name, description in default_processes:
            if not self.repository.is_trusted(exe_name):
                self.trust_process(
                    executable_path=exe_name,
                    process_name=exe_name,
                    reason=f"System default: {description}",
                )
                count += 1

        return count

    def get_trust_statistics(self) -> Dict:
        """
        Get statistics about the trust list.
        
        Returns:
            Dict with stats: total_trusted, by_category, etc.
        """
        trusted = self.get_all_trusted()

        if not trusted:
            return {
                'total_trusted': 0,
                'categories': {},
            }

        # Categorize by process type
        categories: Dict[str, int] = {}
        for proc in trusted:
            # Simple categorization based on name patterns
            if 'system' in proc.process_name.lower() or proc.process_name in ['svchost', 'csrss', 'services']:
                category = 'System'
            elif any(browser in proc.process_name.lower() for browser in ['chrome', 'firefox', 'edge', 'safari']):
                category = 'Browser'
            elif proc.process_name.lower().endswith('.exe'):
                category = 'Application'
            else:
                category = 'Other'

            categories[category] = categories.get(category, 0) + 1

        return {
            'total_trusted': len(trusted),
            'categories': categories,
            'sample_processes': [p.process_name for p in trusted[:10]],
        }

    def clear_cache(self):
        """Clear the in-memory trust cache."""
        self._cache.clear()

    def rebuild_cache(self):
        """Rebuild the in-memory cache from repository."""
        self._cache.clear()
        for proc in self.get_all_trusted():
            self._cache[proc.executable_path.lower()] = proc
