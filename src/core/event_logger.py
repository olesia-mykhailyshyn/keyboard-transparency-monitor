"""Event logging and persistence for detections."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from .models import ProcessDetection, RiskAnalysis, ProcessStatus


class EventLogger:
    """Log detections and user actions to SQLite database."""

    def __init__(self, storage_dir: Path):
        """
        Initialize event logger.
        
        Args:
            storage_dir: Directory for databases
        """
        self.storage_dir = storage_dir
        self.db_path = storage_dir / 'events.db'
        self._initialize_db()

    def _initialize_db(self) -> None:
        """Create database tables if they don't exist."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    pid INTEGER,
                    process_name TEXT,
                    executable_path TEXT,
                    risk_level TEXT,
                    risk_score REAL,
                    reasons TEXT,
                    status TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    user_action TEXT,
                    user_action_time DATETIME
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_events (
                    scan_id TEXT PRIMARY KEY,
                    timestamp DATETIME,
                    processes_found INTEGER,
                    high_risk_count INTEGER,
                    medium_risk_count INTEGER,
                    low_risk_count INTEGER,
                    duration_ms REAL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_actions (
                    action_id TEXT PRIMARY KEY,
                    detection_id TEXT,
                    action_type TEXT,
                    timestamp DATETIME,
                    notes TEXT,
                    FOREIGN KEY(detection_id) REFERENCES detections(detection_id)
                )
            ''')

            conn.commit()

    def log_detection(self, risk_analysis: RiskAnalysis, executable: str) -> str:
        """
        Log a process detection.
        
        Args:
            risk_analysis: RiskAnalysis object
            executable: Full path to executable
            
        Returns:
            Detection ID
        """
        detection_id = str(uuid4())
        now = datetime.now()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            reasons_str = ' | '.join(risk_analysis.reasons)

            cursor.execute('''
                INSERT OR REPLACE INTO detections
                (detection_id, pid, process_name, executable_path, risk_level, risk_score,
                 reasons, status, first_seen, last_seen, user_action, user_action_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection_id,
                risk_analysis.pid,
                risk_analysis.process_name,
                executable,
                risk_analysis.risk_level.value,
                risk_analysis.risk_score,
                reasons_str,
                ProcessStatus.RUNNING.value,
                now,
                now,
                None,
                None,
            ))

            conn.commit()

        return detection_id

    def record_user_action(self, detection_id: str, action_type: str, notes: str = '') -> None:
        """
        Record a user action on a detection (trust, ignore, terminate).
        
        Args:
            detection_id: ID of detection
            action_type: 'trusted', 'ignored', 'terminated', etc.
            notes: Optional notes
        """
        action_id = str(uuid4())
        now = datetime.now()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Update detection status
            status_map = {
                'trusted': ProcessStatus.TRUSTED.value,
                'ignored': ProcessStatus.IGNORED.value,
                'terminated': ProcessStatus.RUNNING.value,
            }
            new_status = status_map.get(action_type, ProcessStatus.RUNNING.value)

            cursor.execute('''
                UPDATE detections
                SET status = ?, user_action = ?, user_action_time = ?
                WHERE detection_id = ?
            ''', (new_status, action_type, now, detection_id))

            # Log action
            cursor.execute('''
                INSERT INTO user_actions
                (action_id, detection_id, action_type, timestamp, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (action_id, detection_id, action_type, now, notes))

            conn.commit()

    def get_recent_detections(self, limit: int = 100) -> List[dict]:
        """
        Get recent detections.
        
        Args:
            limit: Maximum number of detections to return
            
        Returns:
            List of detection records
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM detections
                ORDER BY last_seen DESC
                LIMIT ?
            ''', (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_detection_by_id(self, detection_id: str) -> Optional[dict]:
        """Get a specific detection."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM detections WHERE detection_id = ?
            ''', (detection_id,))

            row = cursor.fetchone()
            return dict(row) if row else None

    def get_actions_for_detection(self, detection_id: str) -> List[dict]:
        """Get all user actions for a detection."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM user_actions WHERE detection_id = ?
                ORDER BY timestamp DESC
            ''', (detection_id,))

            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> dict:
        """Get overall detection statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT
                    COUNT(*) as total_detections,
                    SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
                    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
                    SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk,
                    SUM(CASE WHEN status = 'TRUSTED' THEN 1 ELSE 0 END) as trusted_count,
                    SUM(CASE WHEN status = 'IGNORED' THEN 1 ELSE 0 END) as ignored_count
                FROM detections
            ''')

            row = cursor.fetchone()
            return {
                'total_detections': row[0] or 0,
                'high_risk': row[1] or 0,
                'medium_risk': row[2] or 0,
                'low_risk': row[3] or 0,
                'trusted_count': row[4] or 0,
                'ignored_count': row[5] or 0,
            }
