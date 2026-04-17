"""Unit tests for process scanner."""

import pytest
from src.core.process_scanner import ProcessScanner


@pytest.fixture
def scanner():
    """Create a process scanner instance."""
    return ProcessScanner()


def test_scanner_scan_all_processes(scanner):
    """Test that scanning returns process list."""
    processes = scanner.scan_all_processes()

    # Should find at least some processes
    assert len(processes) > 0

    # Check that processes have required fields
    for process in processes[:5]:  # Check first 5
        assert hasattr(process, 'pid')
        assert hasattr(process, 'name')
        assert process.pid > 0
        assert len(process.name) > 0


def test_scanner_get_process_by_pid(scanner):
    """Test getting a specific process by PID."""
    # Get own process ID
    import os
    own_pid = os.getpid()

    process = scanner.get_process_by_pid(own_pid)
    assert process is not None
    assert process.pid == own_pid


def test_scanner_invalid_pid(scanner):
    """Test handling of invalid PID."""
    # PID that should not exist
    process = scanner.get_process_by_pid(999999)
    assert process is None


def test_scanner_last_scan_time(scanner):
    """Test that last scan time is updated."""
    assert scanner.last_scan_time is None

    scanner.scan_all_processes()
    assert scanner.last_scan_time is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
