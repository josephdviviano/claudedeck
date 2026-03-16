"""Tests for file change attribution — tool call extraction, snapshot diffing, and artifact creation."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from claudedeck.core import Chain, ArtifactRef, TurnData
from claudedeck.hook import (
    extract_tool_calls,
    extract_file_operations,
    get_tool_names,
    _create_artifacts_from_ops,
    attribute_snapshot_changes,
    extract_turns,
)
from claudedeck.snapshot import FileSnapshot, SnapshotDiff


# ---------------------------------------------------------------------------
# Test fixtures: session JSONL with file-modifying tool calls
# ---------------------------------------------------------------------------

def make_write_session():
    """Session where Claude writes a file."""
    return [
        {
            "type": "user",
            "uuid": "user-0001",
            "parentUuid": None,
            "promptId": "prompt-1",
            "message": {"role": "user", "content": "Create a hello.py script"},
            "timestamp": "2026-03-16T12:00:00.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0001",
            "parentUuid": "user-0001",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [
                    {"type": "text", "text": "I'll create that file."},
                    {
                        "type": "tool_use",
                        "id": "toolu_write_001",
                        "name": "Write",
                        "input": {
                            "file_path": "hello.py",
                            "content": "print('hello world')\n",
                        },
                    },
                ],
                "stop_reason": None,
            },
            "requestId": "req_0001",
            "timestamp": "2026-03-16T12:00:05.000Z",
            "sessionId": "test",
        },
        {
            "type": "user",
            "uuid": "user-0002",
            "parentUuid": "asst-0001",
            "message": {
                "role": "user",
                "content": [
                    {"tool_use_id": "toolu_write_001", "type": "tool_result", "content": "File written"},
                ],
            },
            "timestamp": "2026-03-16T12:00:06.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0002",
            "parentUuid": "user-0002",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [{"type": "text", "text": "Done! Created hello.py."}],
                "stop_reason": "end_turn",
            },
            "requestId": "req_0002",
            "timestamp": "2026-03-16T12:00:10.000Z",
            "sessionId": "test",
        },
    ]


def make_edit_session():
    """Session where Claude edits a file."""
    return [
        {
            "type": "user",
            "uuid": "user-0001",
            "parentUuid": None,
            "promptId": "prompt-1",
            "message": {"role": "user", "content": "Fix the typo in main.py"},
            "timestamp": "2026-03-16T12:00:00.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0001",
            "parentUuid": "user-0001",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [
                    {"type": "text", "text": "I'll fix that."},
                    {
                        "type": "tool_use",
                        "id": "toolu_edit_001",
                        "name": "Edit",
                        "input": {
                            "file_path": "main.py",
                            "old_string": "pritn",
                            "new_string": "print",
                        },
                    },
                ],
                "stop_reason": "end_turn",
            },
            "requestId": "req_0001",
            "timestamp": "2026-03-16T12:00:05.000Z",
            "sessionId": "test",
        },
    ]


def make_bash_session():
    """Session where Claude runs a Bash command."""
    return [
        {
            "type": "user",
            "uuid": "user-0001",
            "parentUuid": None,
            "promptId": "prompt-1",
            "message": {"role": "user", "content": "Run the render script"},
            "timestamp": "2026-03-16T12:00:00.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0001",
            "parentUuid": "user-0001",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [
                    {"type": "text", "text": "Running it now."},
                    {
                        "type": "tool_use",
                        "id": "toolu_bash_001",
                        "name": "Bash",
                        "input": {
                            "command": "python render.py > output.mp4",
                            "description": "Run render script",
                        },
                    },
                ],
                "stop_reason": "end_turn",
            },
            "requestId": "req_0001",
            "timestamp": "2026-03-16T12:00:05.000Z",
            "sessionId": "test",
        },
    ]


def make_multi_tool_session():
    """Session where Claude uses Write, then Bash in one turn."""
    return [
        {
            "type": "user",
            "uuid": "user-0001",
            "parentUuid": None,
            "promptId": "prompt-1",
            "message": {"role": "user", "content": "Create and run a script"},
            "timestamp": "2026-03-16T12:00:00.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0001",
            "parentUuid": "user-0001",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [
                    {"type": "text", "text": "Creating script..."},
                    {
                        "type": "tool_use",
                        "id": "toolu_write_001",
                        "name": "Write",
                        "input": {"file_path": "script.py", "content": "print('hi')\n"},
                    },
                ],
                "stop_reason": None,
            },
            "requestId": "req_0001",
            "timestamp": "2026-03-16T12:00:05.000Z",
            "sessionId": "test",
        },
        {
            "type": "user",
            "uuid": "user-0002",
            "parentUuid": "asst-0001",
            "message": {
                "role": "user",
                "content": [
                    {"tool_use_id": "toolu_write_001", "type": "tool_result", "content": "OK"},
                ],
            },
            "timestamp": "2026-03-16T12:00:06.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0002",
            "parentUuid": "user-0002",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [
                    {"type": "text", "text": "Now running it..."},
                    {
                        "type": "tool_use",
                        "id": "toolu_bash_001",
                        "name": "Bash",
                        "input": {"command": "python script.py", "description": "Run script"},
                    },
                ],
                "stop_reason": None,
            },
            "requestId": "req_0002",
            "timestamp": "2026-03-16T12:00:08.000Z",
            "sessionId": "test",
        },
        {
            "type": "user",
            "uuid": "user-0003",
            "parentUuid": "asst-0002",
            "message": {
                "role": "user",
                "content": [
                    {"tool_use_id": "toolu_bash_001", "type": "tool_result", "content": "hi\n"},
                ],
            },
            "timestamp": "2026-03-16T12:00:09.000Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "asst-0003",
            "parentUuid": "user-0003",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": [{"type": "text", "text": "Script ran successfully."}],
                "stop_reason": "end_turn",
            },
            "requestId": "req_0003",
            "timestamp": "2026-03-16T12:00:10.000Z",
            "sessionId": "test",
        },
    ]


# ---------------------------------------------------------------------------
# extract_tool_calls
# ---------------------------------------------------------------------------

class TestExtractToolCalls:
    def test_write_session(self):
        records = make_write_session()
        calls = extract_tool_calls(records, "user-0001", None)
        assert len(calls) == 1
        assert calls[0]["name"] == "Write"
        assert calls[0]["id"] == "toolu_write_001"
        assert calls[0]["input"]["file_path"] == "hello.py"

    def test_edit_session(self):
        records = make_edit_session()
        calls = extract_tool_calls(records, "user-0001", None)
        assert len(calls) == 1
        assert calls[0]["name"] == "Edit"
        assert calls[0]["input"]["file_path"] == "main.py"

    def test_bash_session(self):
        records = make_bash_session()
        calls = extract_tool_calls(records, "user-0001", None)
        assert len(calls) == 1
        assert calls[0]["name"] == "Bash"
        assert "render.py" in calls[0]["input"]["command"]

    def test_multi_tool_session(self):
        records = make_multi_tool_session()
        calls = extract_tool_calls(records, "user-0001", None)
        assert len(calls) == 2
        assert calls[0]["name"] == "Write"
        assert calls[1]["name"] == "Bash"

    def test_no_tool_calls(self):
        records = [
            {
                "type": "user",
                "uuid": "user-0001",
                "parentUuid": None,
                "promptId": "prompt-1",
                "message": {"role": "user", "content": "Hello"},
                "timestamp": "2026-03-16T12:00:00.000Z",
                "sessionId": "test",
            },
            {
                "type": "assistant",
                "uuid": "asst-0001",
                "parentUuid": "user-0001",
                "message": {
                    "role": "assistant",
                    "model": "claude-opus-4-6",
                    "content": [{"type": "text", "text": "Hi!"}],
                    "stop_reason": "end_turn",
                },
                "requestId": "req_0001",
                "timestamp": "2026-03-16T12:00:05.000Z",
                "sessionId": "test",
            },
        ]
        calls = extract_tool_calls(records, "user-0001", None)
        assert calls == []

    def test_scoped_to_turn(self):
        """Tool calls from a different turn should not be included."""
        records = make_write_session() + make_edit_session()
        # Fix UUIDs for second turn
        records[4]["uuid"] = "user-0010"
        records[4]["promptId"] = "prompt-2"
        records[5]["uuid"] = "asst-0010"
        records[5]["parentUuid"] = "user-0010"

        # First turn should only have Write
        calls = extract_tool_calls(records, "user-0001", "user-0010")
        assert len(calls) == 1
        assert calls[0]["name"] == "Write"


# ---------------------------------------------------------------------------
# extract_file_operations
# ---------------------------------------------------------------------------

class TestExtractFileOperations:
    def test_write_op(self):
        calls = [{"name": "Write", "id": "toolu_001", "input": {"file_path": "foo.py", "content": "x"}}]
        ops = extract_file_operations(calls)
        assert len(ops) == 1
        assert ops[0]["tool_name"] == "Write"
        assert ops[0]["file_path"] == "foo.py"
        assert ops[0]["operation"] == "create"
        assert ops[0]["tool_id"] == "toolu_001"

    def test_edit_op(self):
        calls = [{"name": "Edit", "id": "toolu_002", "input": {"file_path": "bar.py", "old_string": "a", "new_string": "b"}}]
        ops = extract_file_operations(calls)
        assert len(ops) == 1
        assert ops[0]["tool_name"] == "Edit"
        assert ops[0]["file_path"] == "bar.py"
        assert ops[0]["operation"] == "modify"

    def test_bash_op(self):
        calls = [{"name": "Bash", "id": "toolu_003", "input": {"command": "python run.py"}}]
        ops = extract_file_operations(calls)
        assert len(ops) == 1
        assert ops[0]["tool_name"] == "Bash"
        assert ops[0]["file_path"] is None  # Unknown for Bash
        assert ops[0]["operation"] == "execute"
        assert ops[0]["command"] == "python run.py"

    def test_read_not_included(self):
        calls = [{"name": "Read", "id": "toolu_004", "input": {"file_path": "config.json"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    def test_glob_not_included(self):
        calls = [{"name": "Glob", "id": "toolu_005", "input": {"pattern": "*.py"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    def test_mixed_tools(self):
        calls = [
            {"name": "Read", "id": "t1", "input": {"file_path": "a.py"}},
            {"name": "Write", "id": "t2", "input": {"file_path": "b.py", "content": "x"}},
            {"name": "Bash", "id": "t3", "input": {"command": "ls"}},
            {"name": "Edit", "id": "t4", "input": {"file_path": "c.py", "old_string": "a", "new_string": "b"}},
        ]
        ops = extract_file_operations(calls)
        assert len(ops) == 3  # Write, Bash, Edit
        assert ops[0]["tool_name"] == "Write"
        assert ops[1]["tool_name"] == "Bash"
        assert ops[2]["tool_name"] == "Edit"

    def test_write_without_file_path(self):
        calls = [{"name": "Write", "id": "t1", "input": {"content": "x"}}]  # Missing file_path
        ops = extract_file_operations(calls)
        assert ops == []


# ---------------------------------------------------------------------------
# get_tool_names
# ---------------------------------------------------------------------------

class TestGetToolNames:
    def test_unique_names(self):
        calls = [
            {"name": "Write", "id": "t1", "input": {}},
            {"name": "Bash", "id": "t2", "input": {}},
            {"name": "Write", "id": "t3", "input": {}},
        ]
        names = get_tool_names(calls)
        assert names == ["Write", "Bash"]

    def test_empty(self):
        assert get_tool_names([]) == []

    def test_preserves_order(self):
        calls = [
            {"name": "Bash", "id": "t1", "input": {}},
            {"name": "Read", "id": "t2", "input": {}},
            {"name": "Write", "id": "t3", "input": {}},
        ]
        names = get_tool_names(calls)
        assert names == ["Bash", "Read", "Write"]


# ---------------------------------------------------------------------------
# _create_artifacts_from_ops
# ---------------------------------------------------------------------------

class TestCreateArtifactsFromOps:
    def test_write_creates_artifact(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hi')\n")
        ops = [{"tool_name": "Write", "tool_id": "t1", "file_path": "hello.py", "operation": "create"}]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert len(arts) == 1
        assert arts[0].filename == "hello.py"
        assert arts[0].attribution == "claude:Write"
        assert arts[0].source_tool_id == "t1"
        assert arts[0].sha256  # Non-empty hash

    def test_edit_creates_artifact(self, tmp_path):
        (tmp_path / "main.py").write_text("print('fixed')\n")
        ops = [{"tool_name": "Edit", "tool_id": "t2", "file_path": "main.py", "operation": "modify"}]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert len(arts) == 1
        assert arts[0].attribution == "claude:Edit"

    def test_bash_ignored(self, tmp_path):
        ops = [{"tool_name": "Bash", "tool_id": "t3", "file_path": None, "operation": "execute", "command": "ls"}]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert arts == []

    def test_missing_file_skipped(self, tmp_path):
        ops = [{"tool_name": "Write", "tool_id": "t1", "file_path": "nonexistent.py", "operation": "create"}]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert arts == []

    def test_absolute_path(self, tmp_path):
        (tmp_path / "abs.py").write_text("x = 1\n")
        ops = [{"tool_name": "Write", "tool_id": "t1", "file_path": str(tmp_path / "abs.py"), "operation": "create"}]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert len(arts) == 1
        assert arts[0].filename == "abs.py"

    def test_deduplication(self, tmp_path):
        (tmp_path / "dup.py").write_text("x = 1\n")
        ops = [
            {"tool_name": "Write", "tool_id": "t1", "file_path": "dup.py", "operation": "create"},
            {"tool_name": "Edit", "tool_id": "t2", "file_path": "dup.py", "operation": "modify"},
        ]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert len(arts) == 1  # Same file, only first op creates artifact

    def test_multiple_files(self, tmp_path):
        (tmp_path / "a.py").write_text("a\n")
        (tmp_path / "b.py").write_text("b\n")
        ops = [
            {"tool_name": "Write", "tool_id": "t1", "file_path": "a.py", "operation": "create"},
            {"tool_name": "Write", "tool_id": "t2", "file_path": "b.py", "operation": "create"},
        ]
        arts = _create_artifacts_from_ops(ops, str(tmp_path))
        assert len(arts) == 2


# ---------------------------------------------------------------------------
# ArtifactRef attribution fields
# ---------------------------------------------------------------------------

class TestArtifactRefAttribution:
    def test_default_attribution(self):
        ref = ArtifactRef(filename="test.py", sha256="a" * 64, size_bytes=100)
        assert ref.attribution == "unknown"
        assert ref.source_tool_id is None

    def test_attribution_in_dict(self):
        ref = ArtifactRef(filename="test.py", sha256="a" * 64, size_bytes=100,
                          attribution="claude:Write", source_tool_id="toolu_001")
        d = ref.to_dict()
        assert d["attribution"] == "claude:Write"
        assert d["source_tool_id"] == "toolu_001"

    def test_source_tool_id_omitted_when_none(self):
        ref = ArtifactRef(filename="test.py", sha256="a" * 64, size_bytes=100,
                          attribution="unattributed")
        d = ref.to_dict()
        assert "source_tool_id" not in d

    def test_from_dict_with_attribution(self):
        d = {"filename": "test.py", "sha256": "a" * 64, "size_bytes": 100,
             "attribution": "claude:Edit", "source_tool_id": "toolu_002"}
        ref = ArtifactRef.from_dict(d)
        assert ref.attribution == "claude:Edit"
        assert ref.source_tool_id == "toolu_002"

    def test_from_dict_backward_compat(self):
        """Old chain records without attribution should default to 'unknown'."""
        d = {"filename": "test.py", "sha256": "a" * 64, "size_bytes": 100}
        ref = ArtifactRef.from_dict(d)
        assert ref.attribution == "unknown"
        assert ref.source_tool_id is None

    def test_attribution_in_chain_hash(self):
        """Attribution should affect the chain hash (it's part of identity)."""
        chain1 = Chain()
        chain1.append_turn(
            prompt="test", response="test",
            artifacts=[ArtifactRef("f.py", "a" * 64, 100, "claude:Write")],
        )
        chain2 = Chain()
        chain2.append_turn(
            prompt="test", response="test",
            artifacts=[ArtifactRef("f.py", "a" * 64, 100, "claude:Edit")],
        )
        # Different attribution → different hash
        assert chain1.head_hash != chain2.head_hash


# ---------------------------------------------------------------------------
# TurnData tool_calls field
# ---------------------------------------------------------------------------

class TestTurnDataToolCalls:
    def test_tool_calls_in_dict(self):
        td = TurnData(
            prompt_hash="a" * 64, response_hash="b" * 64,
            tool_calls=["Write", "Bash"],
        )
        d = td.to_dict()
        assert d["tool_calls"] == ["Write", "Bash"]

    def test_tool_calls_omitted_when_empty(self):
        td = TurnData(prompt_hash="a" * 64, response_hash="b" * 64)
        d = td.to_dict()
        assert "tool_calls" not in d

    def test_from_dict_with_tool_calls(self):
        d = {"prompt_hash": "a" * 64, "response_hash": "b" * 64, "tool_calls": ["Read", "Write"]}
        td = TurnData.from_dict(d)
        assert td.tool_calls == ["Read", "Write"]

    def test_from_dict_backward_compat(self):
        d = {"prompt_hash": "a" * 64, "response_hash": "b" * 64}
        td = TurnData.from_dict(d)
        assert td.tool_calls == []

    def test_from_plaintext_with_tool_calls(self):
        td = TurnData.from_plaintext(
            prompt="hello", response="world",
            tool_calls=["Write", "Bash"],
        )
        assert td.tool_calls == ["Write", "Bash"]


# ---------------------------------------------------------------------------
# extract_turns integration (tool calls included)
# ---------------------------------------------------------------------------

class TestExtractTurnsWithToolCalls:
    def test_write_session_has_tool_calls(self):
        records = make_write_session()
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["tool_calls"] == ["Write"]
        assert len(turns[0]["file_operations"]) == 1
        assert turns[0]["file_operations"][0]["tool_name"] == "Write"
        assert turns[0]["file_operations"][0]["file_path"] == "hello.py"

    def test_multi_tool_session_has_all_calls(self):
        records = make_multi_tool_session()
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["tool_calls"] == ["Write", "Bash"]
        ops = turns[0]["file_operations"]
        assert len(ops) == 2
        assert ops[0]["tool_name"] == "Write"
        assert ops[1]["tool_name"] == "Bash"

    def test_no_tool_session_has_empty_lists(self):
        records = [
            {
                "type": "user", "uuid": "u1", "parentUuid": None,
                "promptId": "p1",
                "message": {"role": "user", "content": "hello"},
                "timestamp": "2026-03-16T12:00:00.000Z", "sessionId": "test",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "role": "assistant", "model": "test",
                    "content": [{"type": "text", "text": "hi"}],
                    "stop_reason": "end_turn",
                },
                "requestId": "r1",
                "timestamp": "2026-03-16T12:00:05.000Z", "sessionId": "test",
            },
        ]
        turns = extract_turns(records)
        assert turns[0]["tool_calls"] == []
        assert turns[0]["file_operations"] == []


# ---------------------------------------------------------------------------
# FileSnapshot capture and diffing
# ---------------------------------------------------------------------------

class TestFileSnapshot:
    def test_capture_tracks_files(self, tmp_path):
        (tmp_path / "a.py").write_text("hello\n")
        (tmp_path / "b.txt").write_text("world\n")
        snap = FileSnapshot.capture(tmp_path)
        assert len(snap.files) == 2
        assert "a.py" in snap.files
        assert "b.txt" in snap.files
        assert snap.timestamp  # Non-empty

    def test_capture_ignores_patterns(self, tmp_path):
        (tmp_path / "keep.py").write_text("x\n")
        sub = tmp_path / "node_modules"
        sub.mkdir()
        (sub / "junk.js").write_text("y\n")
        snap = FileSnapshot.capture(tmp_path, ignore_patterns=["node_modules"])
        assert "keep.py" in snap.files
        assert "node_modules/junk.js" not in snap.files

    def test_capture_empty_dir(self, tmp_path):
        snap = FileSnapshot.capture(tmp_path)
        assert snap.files == {}

    def test_to_dict_and_from_dict(self, tmp_path):
        (tmp_path / "f.py").write_text("x\n")
        snap = FileSnapshot.capture(tmp_path)
        d = snap.to_dict()
        restored = FileSnapshot.from_dict(d)
        assert restored.files == snap.files
        assert restored.timestamp == snap.timestamp

    def test_diff_added(self, tmp_path):
        snap_before = FileSnapshot(files={}, timestamp="t0")
        (tmp_path / "new.py").write_text("new\n")
        snap_after = FileSnapshot.capture(tmp_path)
        diff = snap_before.diff(snap_after)
        assert "new.py" in diff.added
        assert diff.modified == {}
        assert diff.deleted == []

    def test_diff_modified(self, tmp_path):
        (tmp_path / "m.py").write_text("v1\n")
        snap_before = FileSnapshot.capture(tmp_path)
        (tmp_path / "m.py").write_text("v2\n")
        snap_after = FileSnapshot.capture(tmp_path)
        diff = snap_before.diff(snap_after)
        assert "m.py" in diff.modified
        assert diff.added == {}

    def test_diff_deleted(self, tmp_path):
        (tmp_path / "gone.py").write_text("bye\n")
        snap_before = FileSnapshot.capture(tmp_path)
        (tmp_path / "gone.py").unlink()
        snap_after = FileSnapshot.capture(tmp_path)
        diff = snap_before.diff(snap_after)
        assert "gone.py" in diff.deleted
        assert diff.added == {}
        assert diff.modified == {}

    def test_diff_unchanged(self, tmp_path):
        (tmp_path / "same.py").write_text("same\n")
        snap_before = FileSnapshot.capture(tmp_path)
        snap_after = FileSnapshot.capture(tmp_path)
        diff = snap_before.diff(snap_after)
        assert diff.is_empty

    def test_diff_mixed(self, tmp_path):
        (tmp_path / "keep.py").write_text("v1\n")
        (tmp_path / "del.py").write_text("gone\n")
        snap_before = FileSnapshot.capture(tmp_path)

        (tmp_path / "keep.py").write_text("v2\n")
        (tmp_path / "del.py").unlink()
        (tmp_path / "add.py").write_text("new\n")
        snap_after = FileSnapshot.capture(tmp_path)

        diff = snap_before.diff(snap_after)
        assert "keep.py" in diff.modified
        assert "del.py" in diff.deleted
        assert "add.py" in diff.added
        assert not diff.is_empty

    def test_changed_files_property(self):
        diff = SnapshotDiff(
            added={"a.py": "hash_a"},
            modified={"m.py": "hash_m"},
            deleted=["d.py"],
        )
        changed = diff.changed_files
        assert changed == {"a.py": "hash_a", "m.py": "hash_m"}


# ---------------------------------------------------------------------------
# attribute_snapshot_changes (Layer 2 cross-referencing)
# ---------------------------------------------------------------------------

class TestAttributeSnapshotChanges:
    def test_bash_inferred_attribution(self, tmp_path):
        """Files changed during a Bash turn get claude:Bash(inferred)."""
        (tmp_path / "output.mp4").write_bytes(b"\x00" * 100)
        diff = SnapshotDiff(
            added={"output.mp4": "somehash"},
            modified={},
            deleted=[],
        )
        arts = attribute_snapshot_changes(
            diff,
            tool_artifacts=[],
            tool_calls=["Bash"],
            cwd=str(tmp_path),
        )
        assert len(arts) == 1
        assert arts[0].filename == "output.mp4"
        assert arts[0].attribution == "claude:Bash(inferred)"

    def test_unattributed_when_no_tools(self, tmp_path):
        """Files changed with no tool calls get 'unattributed'."""
        (tmp_path / "user_edit.py").write_text("edited\n")
        diff = SnapshotDiff(
            added={},
            modified={"user_edit.py": "somehash"},
            deleted=[],
        )
        arts = attribute_snapshot_changes(
            diff,
            tool_artifacts=[],
            tool_calls=[],
            cwd=str(tmp_path),
        )
        assert len(arts) == 1
        assert arts[0].attribution == "unattributed"

    def test_skips_already_tracked_files(self, tmp_path):
        """Files already tracked by Layer 1 (Write/Edit) are not duplicated."""
        (tmp_path / "script.py").write_text("x\n")
        existing = [ArtifactRef("script.py", "a" * 64, 10, "claude:Write", "t1")]
        diff = SnapshotDiff(
            added={"script.py": "somehash"},
            modified={},
            deleted=[],
        )
        arts = attribute_snapshot_changes(
            diff,
            tool_artifacts=existing,
            tool_calls=["Write"],
            cwd=str(tmp_path),
        )
        assert arts == []  # Already covered

    def test_empty_diff_returns_nothing(self, tmp_path):
        diff = SnapshotDiff(added={}, modified={}, deleted=[])
        arts = attribute_snapshot_changes(diff, [], [], str(tmp_path))
        assert arts == []

    def test_deleted_files_not_tracked(self, tmp_path):
        """Deleted files appear in diff.deleted but shouldn't create artifacts."""
        diff = SnapshotDiff(added={}, modified={}, deleted=["gone.py"])
        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))
        assert arts == []  # changed_files only includes added+modified

    def test_missing_file_skipped(self, tmp_path):
        """If snapshot says file was added but it doesn't exist, skip it."""
        diff = SnapshotDiff(
            added={"phantom.py": "hash"},
            modified={},
            deleted=[],
        )
        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))
        assert arts == []

    def test_mixed_layer1_and_layer2(self, tmp_path):
        """Layer 1 files are skipped, Layer 2 files get proper attribution."""
        (tmp_path / "claude_wrote.py").write_text("from claude\n")
        (tmp_path / "bash_output.txt").write_text("output\n")
        (tmp_path / "user_edit.md").write_text("notes\n")

        layer1 = [ArtifactRef("claude_wrote.py", "a" * 64, 20, "claude:Write", "t1")]
        diff = SnapshotDiff(
            added={
                "claude_wrote.py": "hash1",
                "bash_output.txt": "hash2",
            },
            modified={"user_edit.md": "hash3"},
            deleted=[],
        )
        arts = attribute_snapshot_changes(
            diff,
            tool_artifacts=layer1,
            tool_calls=["Write", "Bash"],
            cwd=str(tmp_path),
        )
        # claude_wrote.py skipped (Layer 1), bash_output.txt and user_edit.md included
        assert len(arts) == 2
        filenames = {a.filename for a in arts}
        assert "bash_output.txt" in filenames
        assert "user_edit.md" in filenames
        # Both get Bash(inferred) because Bash was in tool_calls
        for a in arts:
            assert a.attribution == "claude:Bash(inferred)"

    def test_write_turn_unattributed_extra_files(self, tmp_path):
        """In a Write-only turn, extra changed files are 'unattributed' (no Bash)."""
        (tmp_path / "auto_generated.log").write_text("log\n")

        layer1 = [ArtifactRef("main.py", "a" * 64, 50, "claude:Write", "t1")]
        diff = SnapshotDiff(
            added={"auto_generated.log": "hash1"},
            modified={},
            deleted=[],
        )
        arts = attribute_snapshot_changes(
            diff,
            tool_artifacts=layer1,
            tool_calls=["Write"],
            cwd=str(tmp_path),
        )
        assert len(arts) == 1
        assert arts[0].filename == "auto_generated.log"
        assert arts[0].attribution == "unattributed"
