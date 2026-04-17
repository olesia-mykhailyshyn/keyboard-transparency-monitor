"""Unit tests for risk engine."""

import pytest
from datetime import datetime, timedelta

from src.core.models import ProcessInfo, RiskLevel
from src.core.risk_engine import RiskEngine


@pytest.fixture
def risk_engine():
    """Create a risk engine instance."""
    return RiskEngine()


def test_risk_engine_low_risk_system_process(risk_engine):
    """Test that system processes get LOW risk."""
    process = ProcessInfo(
        pid=100,
        name="svchost.exe",
        executable="C:\\Windows\\System32\\svchost.exe",
        command_line="svchost.exe -k netsvcs",
        create_time=datetime.now().timestamp(),
        is_system=True,
    )

    analysis = risk_engine.analyze(process)
    assert analysis.risk_level == RiskLevel.LOW


def test_risk_engine_newly_started_process(risk_engine):
    """Test that newly started processes get flagged."""
    # Process started 2 minutes ago
    old_time = (datetime.now() - timedelta(minutes=2)).timestamp()

    process = ProcessInfo(
        pid=999,
        name="unknown_app.exe",
        executable="C:\\Users\\test\\unknown_app.exe",
        command_line="unknown_app.exe",
        create_time=old_time,
        is_system=False,
    )

    analysis = risk_engine.analyze(process)
    # Should be flagged for being newly started
    assert analysis.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
    assert any("started" in reason.lower() for reason in analysis.reasons)


def test_risk_engine_suspicious_name(risk_engine):
    """Test detection of suspicious names."""
    process = ProcessInfo(
        pid=1010,
        name="keylogger_app.exe",
        executable="C:\\keylogger_app.exe",
        command_line="keylogger_app.exe",
        create_time=(datetime.now() - timedelta(hours=2)).timestamp(),
        is_system=False,
    )

    analysis = risk_engine.analyze(process)
    # Should be flagged for suspicious name
    assert analysis.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
    assert any("keyword" in reason.lower() or "name" in reason.lower() for reason in analysis.reasons)


def test_risk_engine_trusted_process(risk_engine):
    """Test that trusted processes get LOW risk."""
    risk_engine.trusted_processes.add("notepad.exe")

    process = ProcessInfo(
        pid=500,
        name="notepad.exe",
        executable="C:\\Windows\\notepad.exe",
        command_line="notepad.exe",
        create_time=datetime.now().timestamp(),
        is_system=False,
    )

    analysis = risk_engine.analyze(process)
    assert analysis.risk_level == RiskLevel.LOW
    assert "trusted" in analysis.reasons[0].lower()


def test_risk_engine_multiple_signals(risk_engine):
    """Test process flagged with multiple signals."""
    # Newly started + suspicious name + unusual path
    recent_time = (datetime.now() - timedelta(minutes=1)).timestamp()

    process = ProcessInfo(
        pid=2020,
        name="miner_service.exe",
        executable="C:\\Users\\test\\AppData\\Local\\Temp\\miner_service.exe",
        command_line="miner_service.exe -bg",
        create_time=recent_time,
        is_system=False,
        num_threads=20,
        memory_mb=250.0,
    )

    analysis = risk_engine.analyze(process)
    # Should be high risk due to multiple signals
    assert analysis.risk_level == RiskLevel.HIGH or analysis.risk_level == RiskLevel.MEDIUM
    assert len(analysis.signals) > 1
    assert analysis.risk_score > 40


def test_risk_score_ranges(risk_engine):
    """Test that risk scores are properly bounded."""
    # Very old, system process = low score
    old_process = ProcessInfo(
        pid=1,
        name="explorer.exe",
        executable="C:\\Windows\\explorer.exe",
        command_line="explorer.exe",
        create_time=(datetime.now() - timedelta(days=30)).timestamp(),
        is_system=True,
    )

    analysis = risk_engine.analyze(old_process)
    assert 0 <= analysis.risk_score <= 100
    assert analysis.risk_score < 40


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
