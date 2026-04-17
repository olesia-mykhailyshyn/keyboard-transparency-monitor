"""
User action logger for tracking user decisions and interactions.

This module handles:
- Recording user actions on alerts (block, trust, dismiss, etc.)
- Creating audit trail of user decisions
- Generating user action statistics
- Reviewing user action history
"""

from datetime import datetime, timedelta
from typing import Dict, List
from enum import Enum
from .models import UserAction
from storage.repositories import UserActionRepository


class ActionType(Enum):
    """Types of user actions."""
    BLOCK_PROCESS = "block_process"
    TRUST_PROCESS = "trust_process"
    DISMISS_ALERT = "dismiss_alert"
    ACKNOWLEDGE_ALERT = "acknowledge_alert"
    TERMINATE_PROCESS = "terminate_process"
    IGNORE_PROCESS = "ignore_process"
    REMOVE_FROM_BLOCKLIST = "remove_from_blocklist"
    TOGGLE_PROTECTION = "toggle_protection"
    CHANGE_SETTINGS = "change_settings"


class UserActionLogger:
    """Logs and tracks user interactions with the system."""

    def __init__(self, repository: UserActionRepository):
        """
        Initialize user action logger.
        
        Args:
            repository: UserActionRepository for persistent storage
        """
        self.repository = repository

    def log_block_process(
        self,
        process_name: str,
        executable_path: str,
        reason: str = "",
    ) -> UserAction:
        """
        Log a user decision to block a process.
        
        Args:
            process_name: Name of blocked process
            executable_path: Path to executable
            reason: User-provided reason (optional)
            
        Returns:
            Recorded UserAction
        """
        action = UserAction(
            action_type=ActionType.BLOCK_PROCESS.value,
            process_name=process_name,
            executable_path=executable_path,
            details=f"Process blocked by user. Reason: {reason}" if reason else "Process blocked by user",
            timestamp=datetime.now(),
        )
        self.repository.record_action(action)
        return action

    def log_trust_process(
        self,
        process_name: str,
        executable_path: str,
        reason: str = "",
    ) -> UserAction:
        """
        Log a user decision to trust a process.
        
        Args:
            process_name: Name of trusted process
            executable_path: Path to executable
            reason: User-provided reason (optional)
            
        Returns:
            Recorded UserAction
        """
        action = UserAction(
            action_type=ActionType.TRUST_PROCESS.value,
            process_name=process_name,
            executable_path=executable_path,
            details=f"Process marked as trusted. Reason: {reason}" if reason else "Process marked as trusted",
            timestamp=datetime.now(),
        )
        self.repository.record_action(action)
        return action

    def log_dismiss_alert(
        self,
        process_name: str,
        alert_id: int,
    ) -> UserAction:
        """
        Log dismissal of an alert.
        
        Args:
            process_name: Name of process
            alert_id: ID of alert being dismissed
            
        Returns:
            Recorded UserAction
        """
        action = UserAction(
            action_type=ActionType.DISMISS_ALERT.value,
            process_name=process_name,
            executable_path="",
            details=f"Alert {alert_id} dismissed",
            timestamp=datetime.now(),
        )
        self.repository.record_action(action)
        return action

    def log_terminate_process(
        self,
        process_name: str,
        pid: int,
        executable_path: str = "",
    ) -> UserAction:
        """
        Log termination of a process by user.
        
        Args:
            process_name: Name of terminated process
            pid: Process ID
            executable_path: Path to executable (optional)
            
        Returns:
            Recorded UserAction
        """
        action = UserAction(
            action_type=ActionType.TERMINATE_PROCESS.value,
            process_name=process_name,
            executable_path=executable_path,
            details=f"Process PID {pid} terminated by user",
            timestamp=datetime.now(),
        )
        self.repository.record_action(action)
        return action

    def log_settings_change(
        self,
        setting_name: str,
        old_value: str,
        new_value: str,
    ) -> UserAction:
        """
        Log a settings change by user.
        
        Args:
            setting_name: Name of setting changed
            old_value: Previous value
            new_value: New value
            
        Returns:
            Recorded UserAction
        """
        action = UserAction(
            action_type=ActionType.CHANGE_SETTINGS.value,
            process_name=setting_name,
            executable_path="",
            details=f"Setting '{setting_name}' changed from '{old_value}' to '{new_value}'",
            timestamp=datetime.now(),
        )
        self.repository.record_action(action)
        return action

    def log_custom_action(
        self,
        action_type: str,
        process_name: str,
        details: str,
        executable_path: str = "",
    ) -> UserAction:
        """
        Log a custom user action.
        
        Args:
            action_type: Type of action
            process_name: Associated process name
            details: Details about the action
            executable_path: Path to executable (optional)
            
        Returns:
            Recorded UserAction
        """
        action = UserAction(
            action_type=action_type,
            process_name=process_name,
            executable_path=executable_path,
            details=details,
            timestamp=datetime.now(),
        )
        self.repository.record_action(action)
        return action

    def get_process_actions(self, process_name: str, limit: int = 100) -> List[UserAction]:
        """
        Get all actions related to a specific process.
        
        Args:
            process_name: Name of process
            limit: Maximum number of actions to return
            
        Returns:
            List of UserAction objects for that process
        """
        return self.repository.get_process_actions(process_name, limit)

    def get_actions_by_type(self, action_type: str, limit: int = 100) -> List[UserAction]:
        """
        Get all actions of a specific type.
        
        Args:
            action_type: Type of action to filter by
            limit: Maximum number to return
            
        Returns:
            List of UserAction objects of that type
        """
        all_actions = self.repository.get_process_actions("", limit * 2)
        return [a for a in all_actions if a.action_type == action_type][:limit]

    def get_actions_in_timerange(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100,
    ) -> List[UserAction]:
        """
        Get all actions within a time range.
        
        Args:
            start_time: Start of range
            end_time: End of range
            limit: Maximum number to return
            
        Returns:
            List of UserAction objects in that range
        """
        # This would typically query the repository with date range
        # For now, return empty list (would be implemented in repository)
        return []

    def get_recent_actions(self, limit: int = 100) -> List[UserAction]:
        """
        Get most recent user actions.
        
        Args:
            limit: Number of recent actions to return
            
        Returns:
            List of UserAction objects, most recent first
        """
        # This would query repository for recent actions
        return []

    def get_action_statistics(self, hours: int = 24) -> Dict:
        """
        Get statistics about user actions in a time window.
        
        Args:
            hours: Time window in hours
            
        Returns:
            Dict with stats: total_actions, by_type, most_actioned_processes, etc.
        """
        cutoff = datetime.now() - timedelta(hours=hours)

        # This would query repository for actions in time range
        # For now, return template
        return {
            'total_actions': 0,
            'actions_by_type': {},
            'most_actioned_processes': [],
            'time_window_hours': hours,
        }

    def get_audit_trail(self, process_name: str = "", limit: int = 500) -> List[Dict]:
        """
        Get formatted audit trail of actions.
        
        Args:
            process_name: Filter by process name (empty = all)
            limit: Maximum entries to return
            
        Returns:
            List of formatted audit trail entries
        """
        if process_name:
            actions = self.get_process_actions(process_name, limit)
        else:
            actions = self.get_recent_actions(limit)

        audit_trail = []
        for action in actions:
            audit_trail.append({
                'timestamp': action.timestamp.isoformat(),
                'action': action.action_type,
                'process': action.process_name,
                'details': action.details,
            })

        return audit_trail
