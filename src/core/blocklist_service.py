"""
Blocklist management service for managing blocked processes.

This service handles:
- Adding/removing processes from blocklist
- Tracking relaunch attempts of blocked processes
- Checking if a process is blocked
- Recording block events and attempts
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .models import BlockedProcess, ProcessStatus
from storage.repositories import BlocklistRepository


class BlocklistService:
    """Manages the blocklist of processes to prevent execution."""

    def __init__(self, repository: BlocklistRepository):
        """
        Initialize blocklist service.
        
        Args:
            repository: BlocklistRepository for persistent storage
        """
        self.repository = repository
        self._relaunch_attempts: Dict[str, int] = {}  # Track relaunch attempts in session

    def block_process(
        self,
        executable_path: str,
        process_name: str,
        reason: str,
        risk_score: int,
    ) -> BlockedProcess:
        """
        Add a process to the blocklist.
        
        Args:
            executable_path: Full path to executable
            process_name: Name of the process
            reason: Reason for blocking
            risk_score: Risk score (0-100)
            
        Returns:
            BlockedProcess record
        """
        blocked = BlockedProcess(
            executable_path=executable_path,
            process_name=process_name,
            status=ProcessStatus.BLOCKED,
            reason=reason,
            risk_score=risk_score,
            blocked_at=datetime.now(),
            relaunch_attempts=0,
            last_relaunch_attempt=None,
        )

        self.repository.add_blocked_process(blocked)
        self._relaunch_attempts[executable_path] = 0

        return blocked

    def unblock_process(self, executable_path: str) -> bool:
        """
        Remove a process from the blocklist.
        
        Args:
            executable_path: Path to executable to unblock
            
        Returns:
            True if unblocked successfully, False if not in blocklist
        """
        return self.repository.remove_blocked(executable_path)

    def is_blocked(self, executable_path: str) -> bool:
        """
        Check if a process is on the blocklist.
        
        Args:
            executable_path: Path to check
            
        Returns:
            True if process is blocked
        """
        return self.repository.is_blocked(executable_path)

    def record_relaunch_attempt(self, executable_path: str, pid: int) -> int:
        """
        Record a relaunch attempt of a blocked process.
        
        Args:
            executable_path: Path of blocked process attempting to restart
            pid: Process ID of relaunch attempt
            
        Returns:
            Number of relaunch attempts so far
        """
        if executable_path not in self._relaunch_attempts:
            self._relaunch_attempts[executable_path] = 0

        self._relaunch_attempts[executable_path] += 1

        # Update in repository
        self.repository.record_relaunch_attempt(
            executable_path=executable_path,
            pid=pid,
            attempt_count=self._relaunch_attempts[executable_path],
        )

        return self._relaunch_attempts[executable_path]

    def get_relaunch_attempts(self, executable_path: str) -> int:
        """Get number of relaunch attempts for a blocked process."""
        return self._relaunch_attempts.get(executable_path, 0)

    def get_all_blocked(self) -> List[BlockedProcess]:
        """
        Get all currently blocked processes.
        
        Returns:
            List of BlockedProcess records
        """
        return self.repository.get_all_blocked()

    def get_frequently_blocked(self, hours: int = 24) -> List[tuple]:
        """
        Get processes most frequently blocked in recent time window.
        
        Args:
            hours: Time window in hours
            
        Returns:
            List of (process_name, block_count) tuples, sorted by frequency
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        blocked = self.get_all_blocked()

        # Count blocks per process name
        block_counts: Dict[str, int] = {}
        for proc in blocked:
            if proc.blocked_at >= cutoff_time:
                block_counts[proc.process_name] = block_counts.get(proc.process_name, 0) + 1

        # Sort by frequency
        return sorted(block_counts.items(), key=lambda x: x[1], reverse=True)

    def clear_old_blocks(self, days: int = 30) -> int:
        """
        Clear very old blocklist entries (older than specified days).
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of entries cleared
        """
        cutoff_time = datetime.now() - timedelta(days=days)
        blocked = self.get_all_blocked()

        count = 0
        for proc in blocked:
            # Only clear if very old and no recent relaunch attempts
            if (proc.blocked_at < cutoff_time and
                (proc.last_relaunch_attempt is None or
                 proc.last_relaunch_attempt < cutoff_time)):
                self.unblock_process(proc.executable_path)
                count += 1

        return count

    def get_blocklist_statistics(self) -> Dict:
        """
        Get statistics about the current blocklist.
        
        Returns:
            Dict with stats: total_blocked, avg_risk_score, frequent_names, etc.
        """
        blocked = self.get_all_blocked()

        if not blocked:
            return {
                'total_blocked': 0,
                'avg_risk_score': 0,
                'max_risk_score': 0,
                'min_risk_score': 0,
                'total_relaunch_attempts': 0,
                'most_common_process_names': [],
            }

        risk_scores = [p.risk_score for p in blocked]
        relaunch_attempts = sum(p.relaunch_attempts for p in blocked)

        process_name_counts: Dict[str, int] = {}
        for proc in blocked:
            process_name_counts[proc.process_name] = (
                process_name_counts.get(proc.process_name, 0) + 1
            )

        most_common = sorted(
            process_name_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        return {
            'total_blocked': len(blocked),
            'avg_risk_score': sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            'max_risk_score': max(risk_scores) if risk_scores else 0,
            'min_risk_score': min(risk_scores) if risk_scores else 0,
            'total_relaunch_attempts': relaunch_attempts,
            'most_common_process_names': most_common,
        }
