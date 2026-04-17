"""Windows-specific process monitoring implementation."""

from typing import List, Optional
import psutil

from src.core.models import ProcessInfo
from .base import PlatformMonitor


class WindowsMonitor(PlatformMonitor):
    """Windows process monitoring using psutil."""

    def scan_processes(self) -> List[ProcessInfo]:
        """Scan all processes on Windows."""
        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'ppid']):
            try:
                info = self._extract_info(proc)
                if info:
                    processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def get_process_detail(self, pid: int) -> Optional[ProcessInfo]:
        """Get detailed info about a specific process."""
        try:
            proc = psutil.Process(pid)
            return self._extract_info(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @staticmethod
    def _extract_info(proc: psutil.Process) -> Optional[ProcessInfo]:
        """Extract ProcessInfo from psutil.Process."""
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or 'unknown'
            exe = proc.info['exe'] or ''
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            create_time = proc.info['create_time']
            ppid = proc.info.get('ppid')

            try:
                parent_name = psutil.Process(ppid).name() if ppid else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_name = None

            try:
                username = proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                username = None

            try:
                num_threads = proc.num_threads()
                memory_mb = proc.memory_info().rss / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                num_threads = 0
                memory_mb = 0.0

            is_system = exe.lower().find('system32') >= 0 if exe else False

            return ProcessInfo(
                pid=pid,
                name=name,
                executable=exe,
                command_line=cmdline,
                create_time=create_time,
                parent_pid=ppid,
                parent_name=parent_name,
                username=username,
                num_threads=num_threads,
                memory_mb=memory_mb,
                is_system=is_system,
            )
        except Exception:
            return None
