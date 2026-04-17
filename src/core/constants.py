"""Constants and configuration for risk scoring and detection."""

# Risk Score Thresholds
RISK_SCORE_HIGH_THRESHOLD = 70.0
RISK_SCORE_MEDIUM_THRESHOLD = 40.0
RISK_SCORE_LOW_THRESHOLD = 0.0

# Signal Severity Weights (impact on final score)
SIGNAL_WEIGHTS = {
    'newly_started': 15.0,           # Started < 10 minutes ago
    'no_visible_window': 12.0,       # No GUI window detected
    'unusual_path': 18.0,            # System path or temp directories
    'background_process': 8.0,       # Appears to run in background
    'suspicious_name': 10.0,         # Matches known malware patterns
    'system_process_mimicking': 20.0,  # Tries to look like system process
    'high_memory_usage': 10.0,       # Unusual memory consumption
    'high_thread_count': 8.0,        # Unusual number of threads
    'parent_suspicious': 12.0,       # Parent process is suspicious
    'unknown_publisher': 5.0,        # Not from trusted vendor
}

# Time thresholds
NEWLY_STARTED_THRESHOLD_MINUTES = 10
MEMORY_THRESHOLD_MB = 500.0
THREAD_THRESHOLD = 50

# System process names (Windows)
SYSTEM_PROCESSES = {
    'svchost.exe', 'csrss.exe', 'services.exe', 'lsass.exe',
    'smss.exe', 'winlogon.exe', 'explorer.exe', 'dwm.exe',
    'taskhostw.exe', 'googleupdatecore.exe', 'chrome.exe',
    'firefox.exe', 'notepad.exe', 'powershell.exe', 'cmd.exe',
}

# Suspicious name patterns
SUSPICIOUS_PATTERNS = {
    'keylog', 'sniffer', 'monitor', 'spy', 'trojan',
    'ransomware', 'worm', 'virus', 'malware', 'botnet',
    'miner', 'crypter', 'loader', 'rat', 'backdoor',
}

# Suspicious paths (Windows)
SUSPICIOUS_PATHS = {
    '\\temp\\', '\\tmp\\', '\\appdata\\', '\\roaming\\',
    '\\programdata\\', '%appdata%', '%temp%', 'c:\\windows\\temp',
}

# Recommended actions
RECOMMENDED_ACTIONS = {
    'LOW': 'No immediate action needed. Monitor for changes.',
    'MEDIUM': 'Review process details. Consider terminating if suspicious.',
    'HIGH': 'Recommend immediate investigation or termination.',
}

# Scan intervals (seconds)
SCAN_INTERVAL_DEFAULT = 10
SCAN_INTERVAL_MIN = 2
SCAN_INTERVAL_MAX = 300
