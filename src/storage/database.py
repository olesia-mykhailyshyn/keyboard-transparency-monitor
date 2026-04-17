"""SQLite database schema and connection management."""

import sqlite3
import atexit
from pathlib import Path
from typing import Optional
import os

# Default storage location
DEFAULT_DB_PATH = Path.home() / ".ktm" / "ktm.db"


class Database:
    """SQLite database wrapper for KTM."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize database connection."""
        if isinstance(db_path, str):
            db_path = Path(db_path)
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection: Optional[sqlite3.Connection] = None
        self._connect()
        self._initialize_schema()
        atexit.register(self.close)

    def _connect(self):
        """Establish database connection."""
        self.connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        # Enable foreign keys
        self.connection.execute("PRAGMA foreign_keys = ON")

    def _initialize_schema(self):
        """Create tables if they don't exist."""
        cursor = self.connection.cursor()

        # Processes table - snapshot of detected processes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processes (
                process_id TEXT PRIMARY KEY,
                pid INTEGER,
                name TEXT,
                executable_path TEXT,
                command_line TEXT,
                parent_pid INTEGER,
                parent_name TEXT,
                start_time REAL,
                user_name TEXT,
                memory_mb REAL,
                cpu_percent REAL,
                num_threads INTEGER,
                is_system_process BOOLEAN,
                has_window BOOLEAN,
                executable_hash TEXT,
                detected_at DATETIME
            )
        """)

        # Risk detections table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                detection_id TEXT PRIMARY KEY,
                pid INTEGER,
                process_name TEXT,
                executable_path TEXT,
                risk_score REAL,
                risk_level TEXT,
                input_device_detected BOOLEAN,
                keyboard_indicators TEXT,
                confidence REAL,
                reasons TEXT,
                recommended_action TEXT,
                is_relaunch BOOLEAN,
                detected_at DATETIME,
                FOREIGN KEY(pid) REFERENCES processes(pid)
            )
        """)

        # Blocked processes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_processes (
                blocked_id TEXT PRIMARY KEY,
                executable_path TEXT,
                executable_name TEXT,
                executable_hash TEXT,
                reason TEXT,
                auto_terminate BOOLEAN,
                last_relaunch_attempt DATETIME,
                relaunch_count INTEGER,
                blocked_at DATETIME,
                blocked_by_user TEXT
            )
        """)

        # Trusted processes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trusted_processes (
                trusted_id TEXT PRIMARY KEY,
                executable_path TEXT,
                executable_name TEXT,
                executable_hash TEXT,
                reason TEXT,
                trusted_at DATETIME,
                trusted_by_user TEXT
            )
        """)

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                severity TEXT,
                process_name TEXT,
                pid INTEGER,
                title TEXT,
                message TEXT,
                risk_level TEXT,
                acknowledged BOOLEAN,
                acknowledged_at DATETIME,
                action_taken TEXT,
                created_at DATETIME
            )
        """)

        # User actions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_actions (
                action_id TEXT PRIMARY KEY,
                pid INTEGER,
                process_name TEXT,
                action_type TEXT,
                reason TEXT,
                result TEXT,
                action_time DATETIME
            )
        """)

        # Scan snapshots table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_snapshots (
                scan_id TEXT PRIMARY KEY,
                total_processes INTEGER,
                suspicious_processes INTEGER,
                blocked_relaunches INTEGER,
                duration_ms REAL,
                scanned_at DATETIME
            )
        """)

        # Events table - audit trail
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT,
                process_name TEXT,
                pid INTEGER,
                details TEXT,
                event_time DATETIME
            )
        """)

        # Create indexes for faster queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pid ON processes(pid)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_time ON detections(detected_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_executable ON blocked_processes(executable_path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(created_at)")

        self.connection.commit()

    def execute(self, query: str, params: tuple = ()):
        """Execute a query."""
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        return cursor

    def commit(self):
        """Commit current transaction."""
        self.connection.commit()

    def rollback(self):
        """Rollback current transaction."""
        self.connection.rollback()

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()

    def get_connection(self) -> sqlite3.Connection:
        """Get raw connection for context managers."""
        return self.connection


# Global database instance
_db_instance: Optional[Database] = None


def initialize_database(db_path: Optional[Path] = None) -> Database:
    """Initialize and return the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance


def get_db_connection() -> sqlite3.Connection:
    """Get the database connection from the global instance."""
    global _db_instance
    if _db_instance is None:
        initialize_database()
    return _db_instance.get_connection()
