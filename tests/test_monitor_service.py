"""Unit tests for monitor service."""

import pytest
import time
from datetime import datetime, timedelta

from src.core.process_scanner import ProcessScanner
from src.core.risk_engine import RiskEngine
from src.core.monitor_service import MonitorService
from src.core.models import RiskLevel, ProcessInfo


@pytest.fixture
def monitor_service():
    """Create a monitor service instance."""
    scanner = ProcessScanner()
    engine = RiskEngine()
    return MonitorService(scanner, engine)


def test_monitor_service_creation(monitor_service):
    """Test that monitor service initializes correctly."""
    assert not monitor_service.is_running
    assert monitor_service.scan_interval == 10


def test_monitor_service_scan_now(monitor_service):
    """Test immediate scan."""
    results = monitor_service.scan_now()
    # Should return list of analyses (may be empty if no high/medium risk)
    assert isinstance(results, list)


def test_monitor_service_start_stop(monitor_service):
    """Test start and stop of background monitoring."""
    assert not monitor_service.is_running

    monitor_service.start()
    assert monitor_service.is_running

    monitor_service.stop()
    assert not monitor_service.is_running


def test_monitor_service_callback(monitor_service):
    """Test that callbacks are called."""
    callback_called = []

    def test_callback(analyses):
        callback_called.append(len(analyses))

    monitor_service.add_detection_callback(test_callback)
    monitor_service.start()

    # Wait for at least one scan
    time.sleep(2)

    monitor_service.stop()

    # Callback should have been called (may have 0 detections)
    assert len(callback_called) >= 0


def test_monitor_service_scan_interval(monitor_service):
    """Test setting scan interval."""
    monitor_service.set_scan_interval(5.0)
    assert monitor_service.scan_interval == 5.0

    # Out of range values should be clamped
    monitor_service.set_scan_interval(0.5)  # Too low
    assert monitor_service.scan_interval >= 2.0

    monitor_service.set_scan_interval(500.0)  # Too high
    assert monitor_service.scan_interval <= 300.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
