"""Utility functions for formatting and display."""

from datetime import datetime, timedelta
from .models import RiskLevel


def format_risk_level(risk_level: RiskLevel) -> str:
    """Format risk level for display."""
    return risk_level.value


def format_timestamp(dt: datetime) -> str:
    """Format datetime for display."""
    if not dt:
        return "Unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_time_ago(dt: datetime) -> str:
    """Format time as relative (e.g., '5 minutes ago')."""
    if not dt:
        return "Unknown"

    now = datetime.now()
    delta = now - dt

    if delta.total_seconds() < 60:
        return f"{int(delta.total_seconds())} seconds ago"
    elif delta.total_seconds() < 3600:
        return f"{int(delta.total_seconds() // 60)} minutes ago"
    elif delta.total_seconds() < 86400:
        return f"{int(delta.total_seconds() // 3600)} hours ago"
    else:
        return f"{int(delta.total_seconds() // 86400)} days ago"


def format_memory_mb(mb: float) -> str:
    """Format memory size in MB."""
    if mb < 1000:
        return f"{mb:.1f} MB"
    else:
        return f"{mb / 1024:.1f} GB"


def format_process_name(name: str, max_length: int = 50) -> str:
    """Format process name with optional truncation."""
    if len(name) > max_length:
        return name[:max_length - 3] + "..."
    return name


def get_risk_color(risk_level: RiskLevel) -> str:
    """Get color code for risk level (HTML color or RGB)."""
    colors = {
        RiskLevel.LOW: "#28A745",      # Green
        RiskLevel.MEDIUM: "#FFC107",   # Yellow
        RiskLevel.HIGH: "#DC3545",     # Red
    }
    return colors.get(risk_level, "#6C757D")  # Gray default


def get_risk_icon(risk_level: RiskLevel) -> str:
    """Get emoji/symbol for risk level."""
    icons = {
        RiskLevel.LOW: "✓",
        RiskLevel.MEDIUM: "⚠",
        RiskLevel.HIGH: "✕",
    }
    return icons.get(risk_level, "?")
