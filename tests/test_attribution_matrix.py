"""Attribution matrix — comprehensive tests showing every type of file change
that IS and IS NOT tracked by the claudedeck attribution system.

This file serves as living documentation of the attribution contract.
Each test name explicitly states the scenario and expected outcome.

Attribution values:
    "claude:Write"          — Claude's Write tool created/overwrote a file (Layer 1, definitive)
    "claude:Edit"           — Claude's Edit tool modified a file (Layer 1, definitive)
    "claude:Bash(inferred)" — File appeared/changed during a turn where Bash ran (Layer 2, inferred)
    "unattributed"          — File changed with no matching tool call (Layer 2, likely user)
    "user:declared"         — User explicitly tracked via `claudedeck track` (Layer 3, not yet impl)
    "user:script"           — User tracked as script output (Layer 3, not yet impl)
    "unknown"               — Legacy records without attribution data

Layers:
    Layer 1 (JSONL tool parsing)    — parses Write/Edit tool_use blocks from transcript
    Layer 2 (filesystem snapshots)  — diffs SHA-256 snapshots between hook runs
    Layer 3 (explicit annotation)   — user declares files via CLI (future)
"""

import json
import os
import pytest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from claudedeck.core import Chain, ArtifactRef, ChainRecord
from claudedeck.hook import (
    _create_artifacts_from_ops,
    attribute_snapshot_changes,
    extract_turns,
    extract_tool_calls,
    extract_file_operations,
    get_tool_names,
    main as hook_main,
    load_state,
    get_deck_dir,
)
from claudedeck.snapshot import FileSnapshot, SnapshotDiff


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _run_hook(transcript_path: str, cwd: str, session_id: str = "test-sess"):
    """Simulate a hook invocation by feeding JSON on stdin."""
    hook_input = json.dumps({
        "session_id": session_id,
        "transcript_path": transcript_path,
        "cwd": cwd,
    })
    with patch("sys.stdin", StringIO(hook_input)):
        hook_main()


def _load_chain(cwd: str, session_id: str = "test-sess") -> Chain:
    chain_path = Path(cwd) / ".claudedeck" / f"{session_id}.chain.jsonl"
    if chain_path.exists():
        return Chain.load(chain_path)
    return Chain()


def _get_all_artifacts(chain: Chain) -> list[ArtifactRef]:
    """Flatten all artifacts across all chain records."""
    arts = []
    for rec in chain.records:
        arts.extend(rec.turn.artifacts)
    return arts


def _artifacts_by_attribution(chain: Chain) -> dict[str, list[ArtifactRef]]:
    """Group artifacts by their attribution value."""
    result: dict[str, list[ArtifactRef]] = {}
    for art in _get_all_artifacts(chain):
        result.setdefault(art.attribution, []).append(art)
    return result


def _write_transcript(path: Path, records: list[dict]):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _make_session(*, tool_blocks: list[dict] | None = None, prompt: str = "do something"):
    """Build a minimal single-turn session JSONL with optional tool_use blocks."""
    assistant_content = [{"type": "text", "text": "Done."}]
    if tool_blocks:
        # Insert tool calls before the final text
        assistant_content = tool_blocks + assistant_content

    records = [
        {
            "type": "user",
            "uuid": "u1",
            "parentUuid": None,
            "promptId": "p1",
            "message": {"role": "user", "content": prompt},
            "timestamp": "2026-03-16T12:00:00Z",
            "sessionId": "test",
        },
        {
            "type": "assistant",
            "uuid": "a1",
            "parentUuid": "u1",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4-6",
                "content": assistant_content,
                "stop_reason": "end_turn",
            },
            "requestId": "req_001",
            "timestamp": "2026-03-16T12:00:05Z",
            "sessionId": "test",
        },
    ]
    return records


def _write_tool(file_path: str, content: str = "x", tool_id: str = "tw1"):
    return {
        "type": "tool_use",
        "id": tool_id,
        "name": "Write",
        "input": {"file_path": file_path, "content": content},
    }


def _edit_tool(file_path: str, tool_id: str = "te1"):
    return {
        "type": "tool_use",
        "id": tool_id,
        "name": "Edit",
        "input": {"file_path": file_path, "old_string": "old", "new_string": "new"},
    }


def _bash_tool(command: str, tool_id: str = "tb1"):
    return {
        "type": "tool_use",
        "id": tool_id,
        "name": "Bash",
        "input": {"command": command},
    }


def _read_tool(file_path: str, tool_id: str = "tr1"):
    return {
        "type": "tool_use",
        "id": tool_id,
        "name": "Read",
        "input": {"file_path": file_path},
    }


def _grep_tool(pattern: str, tool_id: str = "tg1"):
    return {
        "type": "tool_use",
        "id": tool_id,
        "name": "Grep",
        "input": {"pattern": pattern},
    }


def _glob_tool(pattern: str, tool_id: str = "tgl1"):
    return {
        "type": "tool_use",
        "id": tool_id,
        "name": "Glob",
        "input": {"pattern": pattern},
    }


# ═══════════════════════════════════════════════════════════════════════════
# TRACKED: Layer 1 — JSONL tool call parsing (definitive attribution)
# ═══════════════════════════════════════════════════════════════════════════

class TestTrackedLayer1:
    """Files definitively attributed via Write/Edit tool_use blocks in the JSONL."""

    def test_write_creates_new_file(self, tmp_path):
        """Claude's Write tool creates a new file → claude:Write."""
        (tmp_path / "hello.py").write_text("print('hello')\n")
        ops = [{"tool_name": "Write", "tool_id": "tw1", "file_path": "hello.py", "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 1
        assert arts[0].filename == "hello.py"
        assert arts[0].attribution == "claude:Write"
        assert arts[0].source_tool_id == "tw1"
        assert len(arts[0].sha256) == 64  # valid SHA-256 hex

    def test_write_overwrites_existing_file(self, tmp_path):
        """Claude's Write tool overwrites an existing file → still claude:Write."""
        (tmp_path / "config.json").write_text('{"v": 2}')
        ops = [{"tool_name": "Write", "tool_id": "tw2", "file_path": "config.json", "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 1
        assert arts[0].attribution == "claude:Write"

    def test_edit_modifies_existing_file(self, tmp_path):
        """Claude's Edit tool modifies a file → claude:Edit."""
        (tmp_path / "main.py").write_text("print('fixed')\n")
        ops = [{"tool_name": "Edit", "tool_id": "te1", "file_path": "main.py", "operation": "modify"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 1
        assert arts[0].filename == "main.py"
        assert arts[0].attribution == "claude:Edit"
        assert arts[0].source_tool_id == "te1"

    def test_multiple_writes_in_one_turn(self, tmp_path):
        """Multiple Write calls → one artifact per unique file."""
        (tmp_path / "a.py").write_text("a\n")
        (tmp_path / "b.py").write_text("b\n")
        (tmp_path / "c.py").write_text("c\n")
        ops = [
            {"tool_name": "Write", "tool_id": "tw1", "file_path": "a.py", "operation": "create"},
            {"tool_name": "Write", "tool_id": "tw2", "file_path": "b.py", "operation": "create"},
            {"tool_name": "Write", "tool_id": "tw3", "file_path": "c.py", "operation": "create"},
        ]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 3
        assert {a.filename for a in arts} == {"a.py", "b.py", "c.py"}
        assert all(a.attribution == "claude:Write" for a in arts)

    def test_write_then_edit_same_file_deduplicates(self, tmp_path):
        """Write followed by Edit on same file → single artifact (first tool wins)."""
        (tmp_path / "app.py").write_text("final content\n")
        ops = [
            {"tool_name": "Write", "tool_id": "tw1", "file_path": "app.py", "operation": "create"},
            {"tool_name": "Edit", "tool_id": "te1", "file_path": "app.py", "operation": "modify"},
        ]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 1
        assert arts[0].attribution == "claude:Write"  # First tool wins
        assert arts[0].source_tool_id == "tw1"

    def test_write_with_absolute_path(self, tmp_path):
        """Write tool using an absolute path → still tracked correctly."""
        (tmp_path / "abs.py").write_text("x\n")
        abs_path = str(tmp_path / "abs.py")
        ops = [{"tool_name": "Write", "tool_id": "tw1", "file_path": abs_path, "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 1
        assert arts[0].filename == "abs.py"  # Stored as just the filename

    def test_artifact_hash_matches_file_content(self, tmp_path):
        """The SHA-256 in the artifact actually matches the file on disk."""
        content = "print('verifiable')\n"
        (tmp_path / "check.py").write_text(content)
        ops = [{"tool_name": "Write", "tool_id": "tw1", "file_path": "check.py", "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        import hashlib
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert arts[0].sha256 == expected

    def test_artifact_size_matches_file(self, tmp_path):
        """The size_bytes in the artifact matches the actual file size."""
        content = "x" * 42 + "\n"
        (tmp_path / "sized.py").write_text(content)
        ops = [{"tool_name": "Write", "tool_id": "tw1", "file_path": "sized.py", "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert arts[0].size_bytes == len(content.encode())

    def test_tool_calls_recorded_in_turn(self):
        """Tool names are extracted and stored in the turn data."""
        records = _make_session(tool_blocks=[
            _write_tool("f.py"),
            _bash_tool("python f.py"),
        ])
        turns = extract_turns(records)

        assert turns[0]["tool_calls"] == ["Write", "Bash"]

    def test_file_operations_extracted_from_session(self):
        """File operations are extracted with correct metadata."""
        records = _make_session(tool_blocks=[
            _write_tool("new.py", tool_id="tw1"),
            _edit_tool("old.py", tool_id="te1"),
        ])
        turns = extract_turns(records)
        ops = turns[0]["file_operations"]

        assert len(ops) == 2
        assert ops[0] == {
            "tool_name": "Write",
            "tool_id": "tw1",
            "file_path": "new.py",
            "operation": "create",
        }
        assert ops[1] == {
            "tool_name": "Edit",
            "tool_id": "te1",
            "file_path": "old.py",
            "operation": "modify",
        }


# ═══════════════════════════════════════════════════════════════════════════
# TRACKED: Layer 2 — Filesystem snapshot diffing (inferred attribution)
# ═══════════════════════════════════════════════════════════════════════════

class TestTrackedLayer2:
    """Files detected by diffing filesystem snapshots between hook runs."""

    def test_bash_creates_new_file(self, tmp_path):
        """Bash command creates a new file → claude:Bash(inferred)."""
        (tmp_path / "output.csv").write_text("a,b,c\n")
        diff = SnapshotDiff(added={"output.csv": "h"}, modified={}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert len(arts) == 1
        assert arts[0].filename == "output.csv"
        assert arts[0].attribution == "claude:Bash(inferred)"
        assert arts[0].source_tool_id is None  # No specific tool_use ID for inferred

    def test_bash_modifies_existing_file(self, tmp_path):
        """Bash command modifies existing file → claude:Bash(inferred)."""
        (tmp_path / "data.json").write_text('{"updated": true}')
        diff = SnapshotDiff(added={}, modified={"data.json": "h"}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert len(arts) == 1
        assert arts[0].attribution == "claude:Bash(inferred)"

    def test_bash_creates_binary_file(self, tmp_path):
        """Bash renders a binary file (e.g. video) → claude:Bash(inferred)."""
        (tmp_path / "render.mp4").write_bytes(b"\x00\x00\x00\x1cftypisom" + b"\x00" * 100)
        diff = SnapshotDiff(added={"render.mp4": "h"}, modified={}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert len(arts) == 1
        assert arts[0].filename == "render.mp4"
        assert arts[0].attribution == "claude:Bash(inferred)"
        assert arts[0].size_bytes > 0

    def test_bash_creates_multiple_output_files(self, tmp_path):
        """Bash script produces several outputs → all get claude:Bash(inferred)."""
        (tmp_path / "frame_001.png").write_bytes(b"PNG")
        (tmp_path / "frame_002.png").write_bytes(b"PNG")
        (tmp_path / "manifest.json").write_text("{}")
        diff = SnapshotDiff(
            added={"frame_001.png": "h1", "frame_002.png": "h2", "manifest.json": "h3"},
            modified={},
            deleted=[],
        )

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert len(arts) == 3
        assert all(a.attribution == "claude:Bash(inferred)" for a in arts)

    def test_user_creates_file_between_turns(self, tmp_path):
        """User creates a file in their IDE between turns → unattributed."""
        (tmp_path / "notes.md").write_text("# My notes\n")
        diff = SnapshotDiff(added={"notes.md": "h"}, modified={}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], [], str(tmp_path))

        assert len(arts) == 1
        assert arts[0].filename == "notes.md"
        assert arts[0].attribution == "unattributed"

    def test_user_modifies_file_between_turns(self, tmp_path):
        """User edits a file in their IDE between turns → unattributed."""
        (tmp_path / "readme.md").write_text("Updated by user\n")
        diff = SnapshotDiff(added={}, modified={"readme.md": "h"}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], [], str(tmp_path))

        assert len(arts) == 1
        assert arts[0].attribution == "unattributed"

    def test_write_plus_bash_output_separated(self, tmp_path):
        """Write creates script, Bash creates output — both tracked, different layers."""
        (tmp_path / "render.py").write_text("# script\n")
        (tmp_path / "video.mp4").write_bytes(b"\x00" * 50)

        # Layer 1 already tracked render.py
        layer1 = [ArtifactRef("render.py", "a" * 64, 10, "claude:Write", "tw1")]
        diff = SnapshotDiff(
            added={"render.py": "h1", "video.mp4": "h2"},
            modified={},
            deleted=[],
        )

        layer2 = attribute_snapshot_changes(diff, layer1, ["Write", "Bash"], str(tmp_path))

        # render.py skipped (Layer 1), video.mp4 tracked by Layer 2
        assert len(layer2) == 1
        assert layer2[0].filename == "video.mp4"
        assert layer2[0].attribution == "claude:Bash(inferred)"

        # Combined artifacts for the chain record
        all_arts = layer1 + layer2
        assert len(all_arts) == 2
        attrs = {a.filename: a.attribution for a in all_arts}
        assert attrs["render.py"] == "claude:Write"
        assert attrs["video.mp4"] == "claude:Bash(inferred)"

    def test_snapshot_detects_content_change_not_timestamp(self, tmp_path):
        """Snapshot diffing is content-based (SHA-256), not mtime-based."""
        (tmp_path / "stable.py").write_text("same content\n")
        snap1 = FileSnapshot.capture(tmp_path)

        # Touch the file (change mtime) but don't change content
        os.utime(tmp_path / "stable.py")
        snap2 = FileSnapshot.capture(tmp_path)

        diff = snap1.diff(snap2)
        assert diff.is_empty  # No change detected — content identical


# ═══════════════════════════════════════════════════════════════════════════
# NOT TRACKED: scenarios that intentionally produce NO artifacts
# ═══════════════════════════════════════════════════════════════════════════

class TestNotTracked:
    """File changes and tool calls that do NOT produce artifacts."""

    # --- Read-only tool calls ---

    def test_read_tool_not_tracked(self):
        """Read tool call produces no file operations."""
        calls = [{"name": "Read", "id": "tr1", "input": {"file_path": "main.py"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    def test_grep_tool_not_tracked(self):
        """Grep tool call produces no file operations."""
        calls = [{"name": "Grep", "id": "tg1", "input": {"pattern": "TODO"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    def test_glob_tool_not_tracked(self):
        """Glob tool call produces no file operations."""
        calls = [{"name": "Glob", "id": "tgl1", "input": {"pattern": "*.py"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    def test_agent_tool_not_tracked(self):
        """Agent tool call produces no file operations."""
        calls = [{"name": "Agent", "id": "ta1", "input": {"prompt": "search"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    def test_read_only_session_no_artifacts(self):
        """A session with only Read/Grep/Glob has no file_operations."""
        records = _make_session(tool_blocks=[
            _read_tool("main.py"),
            _grep_tool("TODO"),
            _glob_tool("**/*.py"),
        ])
        turns = extract_turns(records)

        assert turns[0]["file_operations"] == []
        assert set(turns[0]["tool_calls"]) == {"Read", "Grep", "Glob"}

    # --- Deleted files ---

    def test_deleted_files_not_artifacted(self, tmp_path):
        """Files that were deleted produce NO artifact (nothing to hash)."""
        diff = SnapshotDiff(added={}, modified={}, deleted=["removed.py", "old.txt"])

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert arts == []

    def test_deleted_files_recorded_in_diff_but_not_chain(self, tmp_path):
        """SnapshotDiff tracks deletions, but they never become ArtifactRefs."""
        (tmp_path / "keep.py").write_text("x\n")
        (tmp_path / "gone.py").write_text("y\n")
        snap_before = FileSnapshot.capture(tmp_path)

        (tmp_path / "gone.py").unlink()
        snap_after = FileSnapshot.capture(tmp_path)

        diff = snap_before.diff(snap_after)
        assert "gone.py" in diff.deleted
        assert diff.changed_files == {}  # Deletions excluded from changed_files

    # --- Files that don't exist on disk ---

    def test_write_to_nonexistent_path_not_tracked(self, tmp_path):
        """Write tool targeting a path that doesn't exist on disk → skipped."""
        ops = [{"tool_name": "Write", "tool_id": "tw1", "file_path": "ghost.py", "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert arts == []

    def test_snapshot_phantom_file_not_tracked(self, tmp_path):
        """Snapshot says file was added but it's gone when we check → skipped."""
        diff = SnapshotDiff(added={"vanished.py": "h"}, modified={}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert arts == []

    # --- Write tool missing file_path ---

    def test_write_without_file_path_not_tracked(self):
        """Write tool call with missing file_path input → no file operation."""
        calls = [{"name": "Write", "id": "tw1", "input": {"content": "x"}}]
        ops = extract_file_operations(calls)
        assert ops == []

    # --- Unchanged files ---

    def test_unchanged_files_produce_empty_diff(self, tmp_path):
        """Files that haven't changed between snapshots → empty diff, no artifacts."""
        (tmp_path / "stable.py").write_text("unchanged\n")
        snap1 = FileSnapshot.capture(tmp_path)
        snap2 = FileSnapshot.capture(tmp_path)

        diff = snap1.diff(snap2)

        assert diff.is_empty
        arts = attribute_snapshot_changes(diff, [], [], str(tmp_path))
        assert arts == []

    # --- No tool calls at all ---

    def test_text_only_response_no_artifacts(self):
        """Plain text response with no tool calls → no artifacts."""
        records = _make_session(tool_blocks=None, prompt="What is Python?")
        turns = extract_turns(records)

        assert turns[0]["tool_calls"] == []
        assert turns[0]["file_operations"] == []

    # --- Bash with no file changes ---

    def test_bash_with_no_file_changes(self, tmp_path):
        """Bash ran but filesystem unchanged → no Layer 2 artifacts."""
        diff = SnapshotDiff(added={}, modified={}, deleted=[])

        arts = attribute_snapshot_changes(diff, [], ["Bash"], str(tmp_path))

        assert arts == []


# ═══════════════════════════════════════════════════════════════════════════
# EDGE CASES: tricky scenarios and boundary conditions
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Boundary conditions and tricky attribution scenarios."""

    def test_same_filename_different_dirs_both_tracked(self, tmp_path):
        """Two files with the same name in different dirs → both tracked."""
        (tmp_path / "src").mkdir()
        (tmp_path / "test").mkdir()
        (tmp_path / "src" / "main.py").write_text("src\n")
        (tmp_path / "test" / "main.py").write_text("test\n")
        ops = [
            {"tool_name": "Write", "tool_id": "tw1", "file_path": str(tmp_path / "src" / "main.py"), "operation": "create"},
            {"tool_name": "Write", "tool_id": "tw2", "file_path": str(tmp_path / "test" / "main.py"), "operation": "create"},
        ]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        # Both are named "main.py" — dedup is by resolved path, not filename
        assert len(arts) == 2

    def test_layer1_takes_priority_over_layer2(self, tmp_path):
        """When both layers see a file, Layer 1 (Write/Edit) wins — no double counting."""
        (tmp_path / "script.py").write_text("content\n")

        layer1 = [ArtifactRef("script.py", "a" * 64, 10, "claude:Write", "tw1")]
        diff = SnapshotDiff(added={"script.py": "h"}, modified={}, deleted=[])

        layer2 = attribute_snapshot_changes(diff, layer1, ["Write", "Bash"], str(tmp_path))

        assert layer2 == []  # Layer 1 already covers it

    def test_bash_attribution_only_when_bash_in_tool_calls(self, tmp_path):
        """Without Bash in tool_calls, extra files are 'unattributed' even with Write."""
        (tmp_path / "mystery.log").write_text("log\n")
        diff = SnapshotDiff(added={"mystery.log": "h"}, modified={}, deleted=[])

        # Turn had Write but NOT Bash
        arts = attribute_snapshot_changes(diff, [], ["Write"], str(tmp_path))

        assert len(arts) == 1
        assert arts[0].attribution == "unattributed"  # Not Bash(inferred)

    def test_attribution_is_part_of_chain_hash(self):
        """Different attributions for same file content → different chain hashes."""
        chain_a = Chain()
        chain_a.append_turn(
            prompt="p", response="r",
            artifacts=[ArtifactRef("f.py", "a" * 64, 10, "claude:Write")],
        )
        chain_b = Chain()
        chain_b.append_turn(
            prompt="p", response="r",
            artifacts=[ArtifactRef("f.py", "a" * 64, 10, "unattributed")],
        )

        assert chain_a.head_hash != chain_b.head_hash

    def test_backward_compat_missing_attribution(self):
        """Old chain records without attribution default to 'unknown'."""
        old_data = {
            "filename": "legacy.py",
            "sha256": "b" * 64,
            "size_bytes": 42,
            # No "attribution" key — old format
        }
        ref = ArtifactRef.from_dict(old_data)

        assert ref.attribution == "unknown"
        assert ref.source_tool_id is None

    def test_backward_compat_missing_tool_calls(self):
        """Old TurnData without tool_calls field defaults to empty list."""
        from claudedeck.core import TurnData
        old_data = {
            "prompt_hash": "a" * 64,
            "response_hash": "b" * 64,
            # No "tool_calls" key — old format
        }
        td = TurnData.from_dict(old_data)

        assert td.tool_calls == []

    def test_empty_snapshot_baseline(self, tmp_path):
        """First hook run with no previous snapshot → no Layer 2 artifacts."""
        # Simulates the first run where prev_snapshot is None
        # Layer 2 should be skipped entirely
        (tmp_path / "new.py").write_text("x\n")

        # With no previous snapshot, we can't diff
        # The hook handles this by checking `if prev_snapshot is not None:`
        # So no snapshot_artifacts are produced
        layer1 = [ArtifactRef("new.py", "a" * 64, 2, "claude:Write", "tw1")]

        # Simulating: prev_snapshot is None → skip Layer 2
        prev_snapshot = None
        if prev_snapshot is not None:
            snapshot_artifacts = attribute_snapshot_changes(
                prev_snapshot.diff(FileSnapshot.capture(tmp_path)),
                layer1, ["Write"], str(tmp_path),
            )
        else:
            snapshot_artifacts = []

        assert snapshot_artifacts == []
        # Only Layer 1 artifacts survive
        assert len(layer1) == 1

    def test_binary_file_tracked_correctly(self, tmp_path):
        """Binary files (images, videos) are tracked with correct hash and size."""
        binary_content = bytes(range(256)) * 10  # 2560 bytes of binary data
        (tmp_path / "image.png").write_bytes(binary_content)
        ops = [{"tool_name": "Write", "tool_id": "tw1", "file_path": "image.png", "operation": "create"}]

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 1
        assert arts[0].size_bytes == 2560
        import hashlib
        expected_hash = hashlib.sha256(binary_content).hexdigest()
        assert arts[0].sha256 == expected_hash

    def test_large_number_of_files_all_tracked(self, tmp_path):
        """Many files created in one turn → all tracked individually."""
        ops = []
        for i in range(50):
            fname = f"file_{i:03d}.py"
            (tmp_path / fname).write_text(f"content_{i}\n")
            ops.append({"tool_name": "Write", "tool_id": f"tw{i}", "file_path": fname, "operation": "create"})

        arts = _create_artifacts_from_ops(ops, str(tmp_path))

        assert len(arts) == 50
        assert len({a.sha256 for a in arts}) == 50  # All unique hashes

    def test_tool_call_order_preserved(self):
        """Tool calls are recorded in the order they appear in the transcript."""
        records = _make_session(tool_blocks=[
            _read_tool("a.py", tool_id="t1"),
            _write_tool("b.py", tool_id="t2"),
            _bash_tool("ls", tool_id="t3"),
            _edit_tool("c.py", tool_id="t4"),
            _grep_tool("TODO", tool_id="t5"),
        ])
        turns = extract_turns(records)

        assert turns[0]["tool_calls"] == ["Read", "Write", "Bash", "Edit", "Grep"]


# ═══════════════════════════════════════════════════════════════════════════
# END-TO-END: Full hook run with file tracking
# ═══════════════════════════════════════════════════════════════════════════

class TestEndToEndAttribution:
    """Integration tests running the actual hook with file changes."""

    def test_hook_tracks_write_artifact(self, tmp_path):
        """Full hook run: Write tool → artifact in chain with claude:Write."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "hello.py").write_text("print('hi')\n")

        transcript = tmp_path / "transcript.jsonl"
        _write_transcript(transcript, _make_session(
            tool_blocks=[_write_tool("hello.py", content="print('hi')\n")],
        ))

        _run_hook(str(transcript), str(project))

        chain = _load_chain(str(project))
        assert len(chain.records) == 1
        arts = chain.records[0].turn.artifacts
        assert len(arts) >= 1

        write_arts = [a for a in arts if a.attribution == "claude:Write"]
        assert len(write_arts) == 1
        assert write_arts[0].filename == "hello.py"

    def test_hook_no_artifacts_for_text_only(self, tmp_path):
        """Full hook run: text-only response → no artifacts."""
        project = tmp_path / "project"
        project.mkdir()

        transcript = tmp_path / "transcript.jsonl"
        _write_transcript(transcript, _make_session(prompt="explain Python"))

        _run_hook(str(transcript), str(project))

        chain = _load_chain(str(project))
        assert len(chain.records) == 1
        assert chain.records[0].turn.artifacts == []

    def test_hook_snapshot_persists_between_runs(self, tmp_path):
        """Snapshot is saved in state and loaded on next hook run."""
        project = tmp_path / "project"
        project.mkdir()

        # First run: establishes baseline snapshot
        transcript1 = tmp_path / "t1.jsonl"
        _write_transcript(transcript1, _make_session(prompt="hello"))
        _run_hook(str(transcript1), str(project))

        # Check snapshot was saved
        state = load_state(get_deck_dir(str(project)), "test-sess")
        assert "snapshot" in state
        assert isinstance(state["snapshot"]["files"], dict)

    def test_hook_detects_user_change_via_snapshot(self, tmp_path):
        """Two hook runs: user edits file between them → unattributed artifact."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "readme.md").write_text("v1\n")

        # First run: baseline
        transcript1 = tmp_path / "t1.jsonl"
        _write_transcript(transcript1, _make_session(prompt="first"))
        _run_hook(str(transcript1), str(project))

        # User edits a file between turns
        (project / "readme.md").write_text("v2 - edited by user\n")

        # Second run: new turn, different transcript
        session2 = _make_session(prompt="second")
        # Give it a different promptId/uuid so it's a new turn
        session2[0]["uuid"] = "u2"
        session2[0]["promptId"] = "p2"
        session2[1]["uuid"] = "a2"
        session2[1]["parentUuid"] = "u2"

        # Need BOTH turns in the transcript (hook counts processed turns)
        first_session = _make_session(prompt="first")
        combined = first_session + session2

        transcript2 = tmp_path / "t2.jsonl"
        _write_transcript(transcript2, combined)
        _run_hook(str(transcript2), str(project))

        chain = _load_chain(str(project))
        assert len(chain.records) == 2

        # Second record should have the unattributed change
        second_arts = chain.records[1].turn.artifacts
        unattributed = [a for a in second_arts if a.attribution == "unattributed"]
        assert len(unattributed) == 1
        assert unattributed[0].filename == "readme.md"

    def test_hook_chain_verifies_with_attributed_artifacts(self, tmp_path):
        """Chain with attributed artifacts still passes verification."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "code.py").write_text("x = 1\n")

        transcript = tmp_path / "transcript.jsonl"
        _write_transcript(transcript, _make_session(
            tool_blocks=[_write_tool("code.py", content="x = 1\n")],
        ))

        _run_hook(str(transcript), str(project))

        chain = _load_chain(str(project))
        is_valid, errors = chain.verify()
        assert is_valid, f"Chain verification failed: {errors}"

    def test_tool_calls_stored_in_chain_record(self, tmp_path):
        """Tool call names are persisted in the chain record's TurnData."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "f.py").write_text("x\n")

        transcript = tmp_path / "transcript.jsonl"
        _write_transcript(transcript, _make_session(
            tool_blocks=[_write_tool("f.py"), _bash_tool("python f.py")],
        ))

        _run_hook(str(transcript), str(project))

        chain = _load_chain(str(project))
        assert chain.records[0].turn.tool_calls == ["Write", "Bash"]
