"""Trusted process registry management."""

import json
from pathlib import Path
from typing import Set


class TrustedRegistry:
    """Manage trusted process list persisted to local JSON file."""

    def __init__(self, storage_dir: Path):
        """
        Initialize trusted registry.
        
        Args:
            storage_dir: Directory for storing registry file
        """
        self.storage_dir = storage_dir
        self.registry_file = storage_dir / 'trusted_processes.json'
        self.trusted_processes: Set[str] = self._load()

    def _load(self) -> Set[str]:
        """Load trusted processes from file."""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('trusted_processes', []))
            except (json.JSONDecodeError, IOError):
                return set()
        return set()

    def _save(self) -> None:
        """Save trusted processes to file."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        with open(self.registry_file, 'w') as f:
            json.dump(
                {'trusted_processes': sorted(list(self.trusted_processes))},
                f,
                indent=2,
            )

    def add(self, process_name: str) -> None:
        """Mark a process as trusted."""
        self.trusted_processes.add(process_name.lower())
        self._save()

    def remove(self, process_name: str) -> None:
        """Remove a process from trusted list."""
        self.trusted_processes.discard(process_name.lower())
        self._save()

    def is_trusted(self, process_name: str) -> bool:
        """Check if a process is trusted."""
        return process_name.lower() in self.trusted_processes

    def get_all(self) -> Set[str]:
        """Get all trusted processes."""
        return self.trusted_processes.copy()

    def clear(self) -> None:
        """Clear all trusted processes."""
        self.trusted_processes.clear()
        self._save()
