"""
claudedeck.snapshot — Filesystem snapshot and diffing for change attribution.

Captures SHA-256 checksums of tracked files and computes diffs between
snapshots to detect file additions, modifications, and deletions.
"""

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .core import sha256_file


@dataclass
class FileSnapshot:
    """Checksums of files at a point in time."""
    files: dict[str, str] = field(default_factory=dict)  # relative_path -> sha256
    timestamp: str = ""

    @classmethod
    def capture(
        cls,
        root: Path,
        ignore_patterns: list[str] | None = None,
    ) -> "FileSnapshot":
        """Capture a snapshot of tracked files under root.

        Uses `git ls-files` for the file list when in a git repo,
        falling back to a simple directory walk.
        """
        root = root.resolve()
        files = {}
        paths = _get_tracked_paths(root)

        ignore = set(ignore_patterns or [])

        for rel_path in paths:
            # Apply ignore patterns (simple prefix matching)
            if any(rel_path.startswith(pat) or f"/{pat}" in f"/{rel_path}" for pat in ignore):
                continue

            full_path = root / rel_path
            if not full_path.is_file():
                continue

            try:
                files[rel_path] = sha256_file(full_path)
            except (OSError, PermissionError):
                continue

        return cls(
            files=files,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def diff(self, current: "FileSnapshot") -> "SnapshotDiff":
        """Compare this (previous) snapshot against a current one.

        Returns files that were added, modified, or deleted.
        """
        added = {}
        modified = {}
        deleted = []

        # Files in current but not in self → added
        # Files in both but different hash → modified
        for path, new_hash in current.files.items():
            old_hash = self.files.get(path)
            if old_hash is None:
                added[path] = new_hash
            elif old_hash != new_hash:
                modified[path] = new_hash

        # Files in self but not in current → deleted
        for path in self.files:
            if path not in current.files:
                deleted.append(path)

        return SnapshotDiff(added=added, modified=modified, deleted=deleted)

    def to_dict(self) -> dict:
        return {"files": self.files, "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, d: dict) -> "FileSnapshot":
        return cls(files=d.get("files", {}), timestamp=d.get("timestamp", ""))


@dataclass
class SnapshotDiff:
    """Difference between two file snapshots."""
    added: dict[str, str] = field(default_factory=dict)       # path -> new_hash
    modified: dict[str, str] = field(default_factory=dict)     # path -> new_hash
    deleted: list[str] = field(default_factory=list)

    @property
    def changed_files(self) -> dict[str, str]:
        """All added and modified files (paths with new hashes)."""
        return {**self.added, **self.modified}

    @property
    def is_empty(self) -> bool:
        return not self.added and not self.modified and not self.deleted


def _get_tracked_paths(root: Path) -> list[str]:
    """Get list of tracked file paths relative to root.

    Uses `git ls-files` if in a git repo, including untracked files
    that are not ignored. Falls back to walking the directory.
    """
    try:
        # Get tracked files + untracked non-ignored files
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            paths = [p for p in result.stdout.strip().split("\n") if p]
            return paths
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: walk directory (skip hidden dirs and common build dirs)
    skip_dirs = {".git", ".claudedeck", "node_modules", "__pycache__", ".venv", "venv"}
    paths = []
    for child in sorted(root.rglob("*")):
        if child.is_file():
            rel = str(child.relative_to(root))
            parts = rel.split("/")
            if any(p in skip_dirs for p in parts):
                continue
            paths.append(rel)
    return paths
