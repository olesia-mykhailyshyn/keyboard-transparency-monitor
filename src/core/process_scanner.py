"""
Process scanner for enumerating and collecting metadata about running processes.

This module handles:
- Scanning all running processes
- Collecting process metadata (PID, name, path, cmdline, etc.)
- Calculating process hashes for detection tracking
- Filtering processes by criteria
"""

import os
import hashlib
import psutil
from typing import List, Optional
from .models import ProcessMetadata


class ProcessScanner:
    """Scans and collects metadata about running processes."""

    def __init__(self, include_system: bool = True):
        """
        Initialize process scanner.
        
        Args:
            include_system: Whether to include system processes in scans
        """
        self.include_system = include_system

    def scan_all_processes(self) -> List[ProcessMetadata]:
        """
        Scan all running processes and collect metadata.
        
        Returns:
            List of ProcessMetadata objects for all running processes
        """
        processes: List[ProcessMetadata] = []

        for proc in psutil.process_iter():
            try:
                metadata = self._collect_process_metadata(proc)
                if metadata:
                    processes.append(metadata)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process terminated or access denied
                continue

        return processes

    def scan_by_name(self, process_name: str) -> List[ProcessMetadata]:
        """
        Scan for processes matching a name (partial match, case-insensitive).
        
        Args:
            process_name: Name or partial name to search for
            
        Returns:
            List of matching ProcessMetadata objects
        """
        processes: List[ProcessMetadata] = []
        name_lower = process_name.lower()

        for proc in psutil.process_iter():
            try:
                if name_lower in proc.name().lower():
                    metadata = self._collect_process_metadata(proc)
                    if metadata:
                        processes.append(metadata)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return processes

    def scan_by_pid(self, pid: int) -> Optional[ProcessMetadata]:
        """
        Scan for a specific process by PID.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            ProcessMetadata if process exists, None otherwise
        """
        try:
            proc = psutil.Process(pid)
            return self._collect_process_metadata(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def scan_by_executable(self, executable_path: str) -> List[ProcessMetadata]:
        """
        Scan for processes running a specific executable.
        
        Args:
            executable_path: Full path to executable to search for
            
        Returns:
            List of ProcessMetadata objects running the executable
        """
        processes: List[ProcessMetadata] = []
        exe_lower = executable_path.lower()

        for proc in psutil.process_iter():
            try:
                if proc.exe().lower() == exe_lower:
                    metadata = self._collect_process_metadata(proc)
                    if metadata:
                        processes.append(metadata)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def _collect_process_metadata(self, proc: psutil.Process) -> Optional[ProcessMetadata]:
        """
        Collect detailed metadata about a process.
        
        Args:
            proc: psutil.Process object
            
        Returns:
            ProcessMetadata object or None if collection fails
        """
        try:
            pid = proc.pid
            name = proc.name()
            
            # Determine if system process
            is_system = self._is_system_process(proc)
            if not self.include_system and is_system:
                return None

            # Get executable path
            try:
                executable = proc.exe()
            except (psutil.AccessDenied, FileNotFoundError):
                executable = None

            # Get command line
            try:
                cmdline = ' '.join(proc.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = None

            # Get process creation time
            create_time = proc.create_time()

            # Get resource info
            try:
                memory_info = proc.memory_info()
                memory_mb = memory_info.rss / (1024 ** 2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                memory_mb = 0

            try:
                num_threads = proc.num_threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                num_threads = 0

            # Calculate executable hash if available
            executable_hash = None
            if executable and os.path.exists(executable):
                try:
                    executable_hash = self._calculate_file_hash(executable)
                except (OSError, PermissionError):
                    pass

            # Get parent process info
            try:
                parent_pid = proc.ppid()
                parent_name = psutil.Process(parent_pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_pid = None
                parent_name = None

            return ProcessMetadata(
                pid=pid,
                name=name,
                executable=executable,
                cmdline=cmdline,
                create_time=create_time,
                is_system=is_system,
                memory_mb=memory_mb,
                num_threads=num_threads,
                executable_hash=executable_hash,
                parent_pid=parent_pid,
                parent_name=parent_name,
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _is_system_process(self, proc: psutil.Process) -> bool:
        """
        Determine if a process is a system process.
        
        Uses heuristics: system process names, path location, etc.
        """
        name_lower = proc.name().lower()

        # Known system process names
        system_names = {
            'svchost.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'dwm.exe', 'winlogon.exe', 'smss.exe',
            'spoolsv.exe', 'taskhost.exe', 'taskhostw.exe',
        }

        if name_lower in system_names:
            return True

        # Check if running from system32 or other system directories
        try:
            exe = proc.exe().lower()
            if any(path in exe for path in [
                '\\system32\\', '\\syswow64\\', '\\drivers\\',
                'windows\\system', '/system32/', '/syswow64/',
            ]):
                return True
        except (psutil.AccessDenied, FileNotFoundError):
            pass

        return False

    @staticmethod
    def _calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of a file for identification.
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm (default: sha256)
            
        Returns:
            Hex digest of file hash
        """
        hash_obj = hashlib.new(algorithm)
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (OSError, IOError):
            return ""

    def get_process_info_dict(self, metadata: ProcessMetadata) -> dict:
        """
        Convert ProcessMetadata to human-readable dictionary.
        
        Args:
            metadata: ProcessMetadata object
            
        Returns:
            Dictionary with process information
        """
        return {
            'pid': metadata.pid,
            'name': metadata.name,
            'executable': metadata.executable,
            'cmdline': metadata.cmdline,
            'is_system': metadata.is_system,
            'memory_mb': f"{metadata.memory_mb:.1f}",
            'threads': metadata.num_threads,
            'parent_pid': metadata.parent_pid,
            'parent_name': metadata.parent_name,
        }
