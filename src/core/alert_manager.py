"""
Alert manager for generating and tracking risk alerts.

This module handles:
- Creating alerts based on risk assessments
- Tracking alert status (new, acknowledged, dismissed)
- Recording user actions on alerts
- Generating alert summaries
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .models import Alert, AlertSeverity, RiskLevel, RiskAssessment
from storage.repositories import AlertRepository


class AlertManager:
    """Manages risk alerts and notifications."""

    # Map risk levels to alert severity
    RISK_TO_SEVERITY = {
        RiskLevel.LOW: AlertSeverity.INFO,
        RiskLevel.MEDIUM: AlertSeverity.WARNING,
        RiskLevel.HIGH: AlertSeverity.CRITICAL,
        RiskLevel.CRITICAL: AlertSeverity.CRITICAL,
    }

    def __init__(self, repository: AlertRepository):
        """
        Initialize alert manager.
        
        Args:
            repository: AlertRepository for persistent storage
        """
        self.repository = repository
        self._unacknowledged_count = 0

    def create_alert_from_assessment(
        self,
        assessment: RiskAssessment,
        process_name: str,
        details: str = "",
    ) -> Alert:
        """
        Create an alert from a risk assessment.
        
        Args:
            assessment: RiskAssessment that triggered the alert
            process_name: Name of the process
            details: Additional details about the alert
            
        Returns:
            Alert object
        """
        severity = self.RISK_TO_SEVERITY.get(assessment.risk_level, AlertSeverity.WARNING)

        title = f"Process Risk Detected: {process_name}"

        if assessment.input_device_detected:
            title = f"⚠️ INPUT DEVICE ACCESS: {process_name}"
            severity = AlertSeverity.CRITICAL

        if assessment.risk_level == RiskLevel.CRITICAL and assessment.risk_score > 90:
            title = f"🔴 CRITICAL: {process_name} - Possible keyboard interception!"

        alert = Alert(
            process_name=process_name,
            risk_level=assessment.risk_level,
            risk_score=assessment.risk_score,
            severity=severity,
            title=title,
            description=self._generate_alert_description(assessment),
            details=details,
            timestamp=datetime.now(),
            is_acknowledged=False,
        )

        self.repository.save_alert(alert)
        self._unacknowledged_count += 1

        return alert

    def acknowledge_alert(self, alert_id: int) -> bool:
        """
        Mark an alert as acknowledged by the user.
        
        Args:
            alert_id: ID of alert to acknowledge
            
        Returns:
            True if successfully acknowledged
        """
        result = self.repository.acknowledge_alert(alert_id)
        if result:
            self._unacknowledged_count = max(0, self._unacknowledged_count - 1)
        return result

    def get_unacknowledged_count(self) -> int:
        """
        Get count of unacknowledged alerts.
        
        Returns:
            Number of unacknowledged alerts
        """
        return self._unacknowledged_count

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """
        Get recent alerts.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of Alert objects, newest first
        """
        return self.repository.get_recent_alerts(limit)

    def get_alerts_by_severity(self, severity: AlertSeverity, limit: int = 50) -> List[Alert]:
        """
        Get alerts filtered by severity level.
        
        Args:
            severity: AlertSeverity to filter by
            limit: Maximum number to return
            
        Returns:
            List of matching Alert objects
        """
        all_alerts = self.get_recent_alerts(limit * 2)  # Get extra to filter
        return [a for a in all_alerts if a.severity == severity][:limit]

    def get_alerts_by_process(self, process_name: str, limit: int = 50) -> List[Alert]:
        """
        Get all alerts for a specific process.
        
        Args:
            process_name: Name of process to filter by
            limit: Maximum number to return
            
        Returns:
            List of Alert objects for that process
        """
        all_alerts = self.get_recent_alerts(limit * 2)
        return [a for a in all_alerts if a.process_name == process_name][:limit]

    def get_alerts_in_timerange(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts within a specific time range.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number to return
            
        Returns:
            List of Alert objects in that range
        """
        all_alerts = self.get_recent_alerts(limit * 2)
        return [
            a for a in all_alerts
            if start_time <= a.timestamp <= end_time
        ][:limit]

    def get_critical_alerts_since(self, minutes: int = 60) -> List[Alert]:
        """
        Get critical alerts from the last N minutes.
        
        Args:
            minutes: Time window in minutes
            
        Returns:
            List of critical Alert objects from that window
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        critical = self.get_alerts_by_severity(AlertSeverity.CRITICAL)
        return [a for a in critical if a.timestamp >= cutoff]

    def dismiss_old_alerts(self, days: int = 7) -> int:
        """
        Dismiss (mark as acknowledged) very old alerts.
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of alerts dismissed
        """
        cutoff = datetime.now() - timedelta(days=days)
        all_alerts = self.get_recent_alerts(1000)

        count = 0
        for alert in all_alerts:
            if alert.timestamp < cutoff and not alert.is_acknowledged:
                self.acknowledge_alert(alert.alert_id)
                count += 1

        return count

    def get_alert_statistics(self) -> Dict:
        """
        Get summary statistics about alerts.
        
        Returns:
            Dict with stats: total_alerts, by_severity, by_process, etc.
        """
        recent = self.get_recent_alerts(500)

        if not recent:
            return {
                'total_alerts': 0,
                'unacknowledged': 0,
                'by_severity': {},
                'critical_in_24h': 0,
            }

        severity_counts: Dict[str, int] = {}
        for alert in recent:
            severity = alert.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count critical alerts in last 24 hours
        critical_24h = len(self.get_critical_alerts_since(1440))

        # Count unacknowledged
        unacknowledged = len([a for a in recent if not a.is_acknowledged])

        return {
            'total_alerts': len(recent),
            'unacknowledged': unacknowledged,
            'by_severity': severity_counts,
            'critical_in_24h': critical_24h,
            'sample_alerts': [
                {
                    'process_name': a.process_name,
                    'title': a.title,
                    'severity': a.severity.name,
                    'risk_score': a.risk_score,
                }
                for a in recent[:5]
            ]
        }

    def _generate_alert_description(self, assessment: RiskAssessment) -> str:
        """
        Generate human-readable alert description from assessment.
        
        Args:
            assessment: RiskAssessment object
            
        Returns:
            Formatted description string
        """
        lines = [
            f"Risk Score: {assessment.risk_score}/100",
            f"Risk Level: {assessment.risk_level.name}",
            f"Detected Signals: {len(assessment.detected_signals)}",
        ]

        if assessment.input_device_detected:
            lines.insert(0, "⚠️  INPUT DEVICE ACCESS DETECTED")
            lines.append("Process may be attempting to access keyboard/input devices")

        if assessment.detected_signals:
            lines.append(f"Key Indicators: {', '.join(assessment.detected_signals[:3])}")

        if assessment.confidence > 0.7:
            lines.append(f"Detection Confidence: HIGH ({assessment.confidence:.0%})")
        elif assessment.confidence > 0.4:
            lines.append(f"Detection Confidence: MEDIUM ({assessment.confidence:.0%})")
        else:
            lines.append(f"Detection Confidence: LOW ({assessment.confidence:.0%})")

        return "\n".join(lines)

    def clear_cache(self):
        """Clear any in-memory alert cache."""
        self._unacknowledged_count = 0
