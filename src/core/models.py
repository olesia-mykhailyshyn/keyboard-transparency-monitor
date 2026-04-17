"""Core data models for the Keyboard Transparency Monitor."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import uuid4


class RiskLevel(Enum):
    """Risk classification for processes."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProcessStatus(Enum):
    """Status of a process in relation to blocklist/trusting."""
    NORMAL = "NORMAL"
    TRUSTED = "TRUSTED"
    BLOCKED = "BLOCKED"
    IGNORED = "IGNORED"


class AlertSeverity(Enum):
    """Severity level for alerts."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class ProcessMetadata:
    """Core process information."""
    pid: int
    name: str
    executable_path: str
    command_line: str
    parent_pid: Optional[int]
    parent_name: Optional[str]
    start_time: float  # Unix timestamp
    user: Optional[str]
    create_time: datetime = field(default_factory=datetime.now)
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    num_threads: int = 0
    is_system_process: bool = False
    has_window: Optional[bool] = None  # Platform-dependent
    executable_hash: Optional[str] = None  # SHA256 if computed


@dataclass
class RiskSignal:
    """Individual risk indicator."""
    signal_name: str
    weight: float  # 0.0 to 1.0
    description: str
    is_critical: bool = False  # If True, suggests CRITICAL risk


@dataclass
class RiskAssessment:
    """Complete risk analysis for a process."""
    pid: int
    process_name: str
    risk_score: float  # 0.0 to 100.0
    risk_level: RiskLevel
    signals: List[RiskSignal] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    input_device_detected: bool = False  # Attempted keyboard/input device access
    keyboard_related_indicators: List[str] = field(default_factory=list)
    recommended_action: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.8  # How confident is this assessment (0.0 to 1.0)


@dataclass
class ProcessDetection:
    """A detection event in the system."""
    detection_id: str = field(default_factory=lambda: str(uuid4()))
    pid: int = 0
    process_name: str = ""
    executable_path: str = ""
    risk_assessment: Optional[RiskAssessment] = None
    status: ProcessStatus = ProcessStatus.NORMAL
    is_relaunch_of_blocked: bool = False
    first_detected: datetime = field(default_factory=datetime.now)
    last_detected: datetime = field(default_factory=datetime.now)
    detection_count: int = 1
    user_action: Optional[str] = None  # "trusted", "blocked", "ignored", "terminated"
    user_action_time: Optional[datetime] = None
    user_notes: str = ""


@dataclass
class BlockedProcess:
    """A process added to blocklist."""
    blocked_id: str = field(default_factory=lambda: str(uuid4()))
    executable_path: str = ""
    executable_name: str = ""
    executable_hash: Optional[str] = None
    reason: str = ""
    blocked_at: datetime = field(default_factory=datetime.now)
    auto_terminate: bool = False
    last_relaunch_attempt: Optional[datetime] = None
    relaunch_count: int = 0
    blocked_by_user: str = ""  # Username if tracked


@dataclass
class TrustedProcess:
    """A process added to whitelist."""
    trusted_id: str = field(default_factory=lambda: str(uuid4()))
    executable_path: str = ""
    executable_name: str = ""
    executable_hash: Optional[str] = None
    reason: str = ""
    trusted_at: datetime = field(default_factory=datetime.now)
    trusted_by_user: str = ""


@dataclass 
class Alert:
    """User alert/notification."""
    severity: AlertSeverity
    process_name: str
    pid: int
    title: str
    message: str
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    risk_level: Optional[RiskLevel] = None
    created_at: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    action_taken: Optional[str] = None  # "dismiss", "trust", "block", "terminate"


@dataclass
class ScanSnapshot:
    """Snapshot of a single scan cycle."""
    total_processes: int = 0
    suspicious_processes: int = 0
    blocked_relaunches: int = 0
    duration_ms: float = 0.0
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    detections: List[ProcessDetection] = field(default_factory=list)


@dataclass
class UserAction:
    """Record of user action on a process."""
    pid: int
    process_name: str
    action_type: str  # "trust", "block", "ignore", "terminate", "unblock", "untrust"
    action_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    reason: str = ""
    result: str = ""  # "success", "failed", "pending"


@dataclass
class SystemStatistics:
    """Overall system statistics."""
    total_detections: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    critical_count: int = 0
    trusted_processes: int = 0
    blocked_processes: int = 0
    blocked_relaunch_count: int = 0
    total_alerts: int = 0
    last_scan: Optional[datetime] = None
    uptime_seconds: float = 0.0
