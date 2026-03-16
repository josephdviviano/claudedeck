"""
tests/test_atomic_write.py — Tests for atomic write and file locking utilities.
"""

import os
import threading
from pathlib import Path

import pytest

from claudedeck.core import atomic_write, file_lock


class TestAtomicWrite:

    def test_creates_file(self, tmp_path):
        path = tmp_path / "test.txt"
        atomic_write(path, "hello")
        assert path.read_text() == "hello"

    def test_replaces_existing_file(self, tmp_path):
        path = tmp_path / "test.txt"
        path.write_text("old content")
        atomic_write(path, "new content")
        assert path.read_text() == "new content"

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "subdir" / "deep" / "test.txt"
        atomic_write(path, "content")
        assert path.read_text() == "content"

    def test_callable_data(self, tmp_path):
        """Supports writing via callback for streaming."""
        path = tmp_path / "stream.txt"

        def writer(f):
            f.write("line 1\n")
            f.write("line 2\n")

        atomic_write(path, writer)
        assert path.read_text() == "line 1\nline 2\n"

    def test_failed_write_preserves_original(self, tmp_path):
        """If the write callback raises, original file is untouched."""
        path = tmp_path / "preserve.txt"
        path.write_text("original")

        def bad_writer(f):
            f.write("partial")
            raise RuntimeError("simulated crash")

        with pytest.raises(RuntimeError):
            atomic_write(path, bad_writer)

        assert path.read_text() == "original", "Original file preserved after failure"

    def test_no_temp_files_left_on_failure(self, tmp_path):
        """Temp files are cleaned up on failure."""
        path = tmp_path / "cleanup.txt"

        def bad_writer(f):
            raise RuntimeError("crash")

        with pytest.raises(RuntimeError):
            atomic_write(path, bad_writer)

        # No temp files should remain
        remaining = list(tmp_path.glob(".*"))
        assert len(remaining) == 0, f"Temp files left: {remaining}"


class TestFileLock:

    def test_basic_lock_and_release(self, tmp_path):
        """Lock can be acquired and released."""
        lock_path = tmp_path / "test"
        with file_lock(lock_path):
            pass  # Lock held during this block

    def test_concurrent_access_serialized(self, tmp_path):
        """Two threads holding the lock produce serialized (non-interleaved) output."""
        lock_path = tmp_path / "concurrent"
        results = []
        import time

        def worker(worker_id):
            with file_lock(lock_path):
                results.append(f"start-{worker_id}")
                time.sleep(0.05)  # Hold lock briefly
                results.append(f"end-{worker_id}")

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        # Both threads completed
        assert len(results) == 4
        # Execution is serialized: start-X, end-X, start-Y, end-Y
        # (no interleaving like start-1, start-2, end-1, end-2)
        assert results[0].startswith("start")
        assert results[1].startswith("end")
        assert results[0].split("-")[1] == results[1].split("-")[1]

    def test_creates_parent_directory(self, tmp_path):
        lock_path = tmp_path / "subdir" / "lock"
        with file_lock(lock_path):
            pass
        assert (tmp_path / "subdir").is_dir()
