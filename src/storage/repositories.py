"""Data access layer using repository pattern."""

from datetime import datetime
from typing import List, Optional
from src.core.models import (
    ProcessDetection, BlockedProcess, TrustedProcess, Alert, UserAction,
    ScanSnapshot, RiskLevel, AlertSeverity
)
from src.storage.database import Database
import json


class DetectionRepository:
    """Repository for process detections."""

    def __init__(self, db: Database):
        self.db = db

    def save_detection(self, detection: ProcessDetection) -> str:
        """Save a detection record."""
        cursor = self.db.execute("""
            INSERT OR REPLACE INTO detections
            (detection_id, pid, process_name, executable_path, risk_score, risk_level,
             input_device_detected, keyboard_indicators, confidence, reasons,
             recommended_action, is_relaunch, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            detection.detection_id,
            detection.pid,
            detection.process_name,
            detection.executable_path,
            detection.risk_assessment.risk_score if detection.risk_assessment else 0,
            detection.risk_assessment.risk_level.value if detection.risk_assessment else "LOW",
            detection.risk_assessment.input_device_detected if detection.risk_assessment else False,
            json.dumps(detection.risk_assessment.keyboard_related_indicators) if detection.risk_assessment else "[]",
            detection.risk_assessment.confidence if detection.risk_assessment else 0.8,
            json.dumps(detection.risk_assessment.reasons) if detection.risk_assessment else "[]",
            detection.risk_assessment.recommended_action if detection.risk_assessment else "",
            detection.is_relaunch_of_blocked,
            detection.first_detected
        ))
        self.db.commit()
        return detection.detection_id

    def get_recent_detections(self, limit: int = 100) -> List[dict]:
        """Get recent detections."""
        cursor = self.db.execute("""
            SELECT * FROM detections
            ORDER BY detected_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_high_risk_detections(self) -> List[dict]:
        """Get recent HIGH and CRITICAL risk detections."""
        cursor = self.db.execute("""
            SELECT * FROM detections
            WHERE risk_level IN ('HIGH', 'CRITICAL')
            ORDER BY detected_at DESC
            LIMIT 50
        """)
        return [dict(row) for row in cursor.fetchall()]


class BlocklistRepository:
    """Repository for blocked processes."""

    def __init__(self, db: Database):
        self.db = db

    def add_blocked_process(self, blocked: BlockedProcess) -> str:
        """Add process to blocklist."""
        cursor = self.db.execute("""
            INSERT INTO blocked_processes
            (blocked_id, executable_path, executable_name, executable_hash, reason,
             auto_terminate, blocked_at, blocked_by_user)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            blocked.blocked_id,
            blocked.executable_path,
            blocked.executable_name,
            blocked.executable_hash,
            blocked.reason,
            blocked.auto_terminate,
            blocked.blocked_at,
            blocked.blocked_by_user
        ))
        self.db.commit()
        return blocked.blocked_id

    def get_all_blocked(self) -> List[dict]:
        """Get all blocked processes."""
        cursor = self.db.execute("SELECT * FROM blocked_processes")
        return [dict(row) for row in cursor.fetchall()]

    def is_blocked(self, executable_path: str) -> bool:
        """Check if executable is in blocklist."""
        cursor = self.db.execute(
            "SELECT blocked_id FROM blocked_processes WHERE executable_path = ? LIMIT 1",
            (executable_path,)
        )
        return cursor.fetchone() is not None

    def remove_blocked(self, blocked_id: str):
        """Remove from blocklist."""
        self.db.execute("DELETE FROM blocked_processes WHERE blocked_id = ?", (blocked_id,))
        self.db.commit()

    def record_relaunch_attempt(self, executable_path: str):
        """Record relaunch attempt of blocked process."""
        cursor = self.db.execute("""
            UPDATE blocked_processes
            SET last_relaunch_attempt = ?, relaunch_count = relaunch_count + 1
            WHERE executable_path = ?
        """, (datetime.now(), executable_path))
        self.db.commit()


class TrustlistRepository:
    """Repository for trusted processes."""

    def __init__(self, db: Database):
        self.db = db

    def add_trusted_process(self, trusted: TrustedProcess) -> str:
        """Add process to trustlist."""
        cursor = self.db.execute("""
            INSERT INTO trusted_processes
            (trusted_id, executable_path, executable_name, executable_hash, reason,
             trusted_at, trusted_by_user)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            trusted.trusted_id,
            trusted.executable_path,
            trusted.executable_name,
            trusted.executable_hash,
            trusted.reason,
            trusted.trusted_at,
            trusted.trusted_by_user
        ))
        self.db.commit()
        return trusted.trusted_id

    def get_all_trusted(self) -> List[dict]:
        """Get all trusted processes."""
        cursor = self.db.execute("SELECT * FROM trusted_processes")
        return [dict(row) for row in cursor.fetchall()]

    def is_trusted(self, executable_path: str) -> bool:
        """Check if executable is whitelisted."""
        cursor = self.db.execute(
            "SELECT trusted_id FROM trusted_processes WHERE executable_path = ? LIMIT 1",
            (executable_path,)
        )
        return cursor.fetchone() is not None

    def remove_trusted(self, trusted_id: str):
        """Remove from trustlist."""
        self.db.execute("DELETE FROM trusted_processes WHERE trusted_id = ?", (trusted_id,))
        self.db.commit()


class AlertRepository:
    """Repository for alerts."""

    def __init__(self, db: Database):
        self.db = db

    def save_alert(self, alert: Alert) -> str:
        """Save an alert."""
        cursor = self.db.execute("""
            INSERT INTO alerts
            (alert_id, severity, process_name, pid, title, message, risk_level,
             acknowledged, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.alert_id,
            alert.severity.value,
            alert.process_name,
            alert.pid,
            alert.title,
            alert.message,
            alert.risk_level.value if alert.risk_level else None,
            alert.acknowledged,
            alert.created_at
        ))
        self.db.commit()
        return alert.alert_id

    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        """Get recent alerts."""
        cursor = self.db.execute("""
            SELECT * FROM alerts
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def acknowledge_alert(self, alert_id: str):
        """Mark alert as acknowledged."""
        cursor = self.db.execute("""
            UPDATE alerts
            SET acknowledged = 1, acknowledged_at = ?
            WHERE alert_id = ?
        """, (datetime.now(), alert_id))
        self.db.commit()


class UserActionRepository:
    """Repository for user actions."""

    def __init__(self, db: Database):
        self.db = db

    def record_action(self, action: UserAction) -> str:
        """Record user action."""
        cursor = self.db.execute("""
            INSERT INTO user_actions
            (action_id, pid, process_name, action_type, reason, result, action_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            action.action_id,
            action.pid,
            action.process_name,
            action.action_type,
            action.reason,
            action.result,
            action.timestamp
        ))
        self.db.commit()
        return action.action_id

    def get_process_actions(self, pid: int) -> List[dict]:
        """Get all actions for a process."""
        cursor = self.db.execute("""
            SELECT * FROM user_actions
            WHERE pid = ?
            ORDER BY action_time DESC
        """, (pid,))
        return [dict(row) for row in cursor.fetchall()]


class StatisticsRepository:
    """Repository for system statistics."""

    def __init__(self, db: Database):
        self.db = db

    def get_statistics(self) -> dict:
        """Get overall statistics."""
        cursor = self.db.execute("""
            SELECT
                COUNT(*) as total_detections,
                SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
                MAX(detected_at) as last_detection
            FROM detections
        """)
        row = cursor.fetchone()
        return dict(row) if row else {}

    def get_blocklist_stats(self) -> dict:
        """Get blocklist statistics."""
        cursor = self.db.execute("""
            SELECT
                COUNT(*) as total_blocked,
                SUM(CASE WHEN relaunch_count > 0 THEN 1 ELSE 0 END) as relaunched
            FROM blocked_processes
        """)
        row = cursor.fetchone()
        return dict(row) if row else {}
