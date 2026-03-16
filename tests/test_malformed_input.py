"""
tests/test_malformed_input.py — Malformed and adversarial input handling.

Tests for robustness against malformed JSONL, missing fields, edge cases
in turn extraction, and adversarial record structures.

Audit ref: Critical gap — 0 tests existed for malformed input handling.
"""

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from claudedeck.hook import (
    read_jsonl, extract_turns, main as hook_main,
    _extract_prompt_text, _flatten_assistant_content,
    extract_tool_calls, extract_file_operations,
)
from claudedeck.core import Chain
from tests.conftest import make_session_jsonl


def _write_jsonl(path, records):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _write_raw_lines(path, lines):
    """Write raw strings as lines (not JSON-encoded)."""
    with open(path, "w") as f:
        for line in lines:
            f.write(line + "\n")


def _run_hook(session_id, transcript_path, cwd):
    hook_input = json.dumps({
        "session_id": session_id,
        "transcript_path": str(transcript_path),
        "cwd": str(cwd),
    })
    with patch("sys.stdin", io.StringIO(hook_input)):
        hook_main()


# ---------------------------------------------------------------------------
# Malformed JSONL files
# ---------------------------------------------------------------------------

class TestMalformedJSONL:

    def test_invalid_json_line_skipped(self, tmp_path):
        """FIXED: Invalid JSON lines are skipped, valid records returned."""
        path = tmp_path / "bad.jsonl"
        _write_raw_lines(path, [
            '{"valid": true}',
            'NOT VALID JSON{{{',
            '{"also_valid": true}',
        ])
        records = read_jsonl(str(path))
        assert len(records) == 2
        assert records[0] == {"valid": True}
        assert records[1] == {"also_valid": True}

    def test_empty_file_returns_empty_list(self, tmp_path):
        """Empty JSONL file returns no records."""
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        records = read_jsonl(str(path))
        assert records == []

    def test_whitespace_only_file(self, tmp_path):
        """File with only whitespace returns no records."""
        path = tmp_path / "whitespace.jsonl"
        path.write_text("   \n\n  \n")
        records = read_jsonl(str(path))
        assert records == []


# ---------------------------------------------------------------------------
# Missing fields in records
# ---------------------------------------------------------------------------

class TestMissingFields:

    def test_records_without_type_field_ignored(self):
        """Records missing 'type' are not processed as turns."""
        records = [
            {"uuid": "u1", "message": {"content": "hello"}},  # No type
            {
                "type": "user", "uuid": "u2", "promptId": "p1",
                "message": {"content": "real prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u2",
                "message": {
                    "model": "test", "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "response"}],
                },
                "requestId": "r1", "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert len(turns) == 1

    def test_user_without_promptid_not_treated_as_turn_start(self):
        """User messages without promptId (tool results) don't start turns."""
        records = [
            {
                "type": "user", "uuid": "u1",
                # No promptId — this is a tool_result relay
                "message": {"content": "tool output"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "model": "test", "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "response"}],
                },
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert len(turns) == 0, "No promptId → not a real user prompt"

    def test_assistant_without_stop_reason(self):
        """An assistant message with no stop_reason can still be found
        as the last assistant message in a turn."""
        records = [
            {
                "type": "user", "uuid": "u1", "promptId": "p1",
                "parentUuid": None,
                "message": {"content": "prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "model": "test",
                    "content": [{"type": "text", "text": "response without stop_reason"}],
                    # No stop_reason
                },
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        # _find_final_response falls back to last assistant message
        assert len(turns) == 1
        assert "response without stop_reason" in turns[0]["response"]

    def test_assistant_with_empty_content(self):
        """Assistant message with empty content list."""
        records = [
            {
                "type": "user", "uuid": "u1", "promptId": "p1",
                "parentUuid": None,
                "message": {"content": "prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "model": "test", "stop_reason": "end_turn",
                    "content": [],  # Empty
                },
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["response"] == ""

    def test_user_with_no_message(self):
        """User record missing 'message' entirely."""
        records = [
            {
                "type": "user", "uuid": "u1", "promptId": "p1",
                # No message field
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "model": "test", "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "response"}],
                },
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["prompt"] == ""  # _extract_prompt_text handles missing message


# ---------------------------------------------------------------------------
# Content extraction edge cases
# ---------------------------------------------------------------------------

class TestContentExtractionEdgeCases:

    def test_prompt_with_mixed_block_types(self):
        """User message with text + non-text blocks."""
        msg = {
            "message": {
                "content": [
                    {"type": "text", "text": "part one"},
                    {"type": "image", "data": "..."},  # Should be ignored
                    {"type": "text", "text": "part two"},
                ]
            }
        }
        result = _extract_prompt_text(msg)
        assert result == "part one\npart two"

    def test_prompt_as_plain_string(self):
        """User message content as a plain string (not blocks)."""
        msg = {"message": {"content": "just a string"}}
        result = _extract_prompt_text(msg)
        assert result == "just a string"

    def test_assistant_content_with_tool_use(self):
        """Tool use blocks are represented as markers."""
        msg = {
            "message": {
                "content": [
                    {"type": "text", "text": "Let me check."},
                    {"type": "tool_use", "name": "Read", "id": "t1", "input": {}},
                ]
            }
        }
        result = _flatten_assistant_content(msg)
        assert "Let me check." in result
        assert "[tool_use: Read]" in result

    def test_assistant_content_with_unknown_block_type(self):
        """Unknown block types are silently skipped."""
        msg = {
            "message": {
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "unknown_future_type", "data": "..."},
                ]
            }
        }
        result = _flatten_assistant_content(msg)
        assert result == "hello"


# ---------------------------------------------------------------------------
# Tool call extraction edge cases
# ---------------------------------------------------------------------------

class TestToolCallEdgeCases:

    def test_tool_call_missing_name(self):
        """Tool use block without 'name' field defaults to 'unknown'."""
        records = [
            {
                "type": "user", "uuid": "u1", "promptId": "p1",
                "message": {"content": "prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "model": "test", "stop_reason": "end_turn",
                    "content": [
                        {"type": "tool_use", "id": "t1", "input": {}},
                        # No "name" key
                    ],
                },
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        calls = extract_tool_calls(records, "u1", None)
        assert len(calls) == 1
        assert calls[0]["name"] == "unknown"

    def test_tool_call_missing_input(self):
        """Tool use block without 'input' defaults to empty dict."""
        records = [
            {
                "type": "user", "uuid": "u1", "promptId": "p1",
                "message": {"content": "prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "model": "test", "stop_reason": "end_turn",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "Read"},
                        # No "input" key
                    ],
                },
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        calls = extract_tool_calls(records, "u1", None)
        assert calls[0]["input"] == {}


# ---------------------------------------------------------------------------
# File operation edge cases
# ---------------------------------------------------------------------------

class TestFileOperationEdgeCases:

    def test_write_without_file_path(self):
        """Write tool call with no file_path in input is skipped."""
        calls = [{"name": "Write", "id": "t1", "input": {"content": "hello"}}]
        ops = extract_file_operations(calls)
        assert len(ops) == 0

    def test_edit_without_file_path(self):
        """Edit tool call with no file_path in input is skipped."""
        calls = [{"name": "Edit", "id": "t1", "input": {"old_string": "a", "new_string": "b"}}]
        ops = extract_file_operations(calls)
        assert len(ops) == 0

    def test_bash_creates_execute_operation(self):
        """Bash tool call creates an execute operation."""
        calls = [{"name": "Bash", "id": "t1", "input": {"command": "echo hello"}}]
        ops = extract_file_operations(calls)
        assert len(ops) == 1
        assert ops[0]["operation"] == "execute"
        assert ops[0]["command"] == "echo hello"

    def test_unknown_tool_ignored(self):
        """Tools not in FILE_WRITE_TOOLS or FILE_EXEC_TOOLS are ignored."""
        calls = [
            {"name": "Read", "id": "t1", "input": {"file_path": "/etc/passwd"}},
            {"name": "Grep", "id": "t2", "input": {"pattern": "secret"}},
            {"name": "Glob", "id": "t3", "input": {"pattern": "*.py"}},
        ]
        ops = extract_file_operations(calls)
        assert len(ops) == 0


# ---------------------------------------------------------------------------
# Hook resilience
# ---------------------------------------------------------------------------

class TestHookResilience:

    def test_hook_with_empty_stdin(self):
        """Hook handles empty stdin gracefully (no crash)."""
        with patch("sys.stdin", io.StringIO("")):
            hook_main()  # Should return without error

    def test_hook_with_invalid_json_stdin(self):
        """Hook handles invalid JSON on stdin gracefully."""
        with patch("sys.stdin", io.StringIO("not json")):
            hook_main()  # Should return without error

    def test_hook_with_missing_transcript_path(self, tmp_path):
        """Hook handles missing transcript_path gracefully."""
        hook_input = json.dumps({
            "session_id": "test",
            "transcript_path": str(tmp_path / "nonexistent.jsonl"),
            "cwd": str(tmp_path),
        })
        with patch("sys.stdin", io.StringIO(hook_input)):
            hook_main()  # Should return without error

    def test_hook_with_empty_session_id(self, tmp_path):
        """Hook handles empty session_id."""
        records = make_session_jsonl([("p", "r", "model")])
        transcript = tmp_path / "t.jsonl"
        _write_jsonl(transcript, records)

        hook_input = json.dumps({
            "session_id": "",
            "transcript_path": str(transcript),
            "cwd": str(tmp_path),
        })
        with patch("sys.stdin", io.StringIO(hook_input)):
            hook_main()  # Should not crash

    def test_hook_with_no_turns_in_transcript(self, tmp_path):
        """Hook processes a transcript with no extractable turns."""
        # JSONL with only assistant messages (no user with promptId)
        transcript = tmp_path / "no_turns.jsonl"
        _write_jsonl(transcript, [
            {
                "type": "assistant", "uuid": "a1",
                "message": {
                    "model": "test",
                    "content": [{"type": "text", "text": "orphaned response"}],
                    "stop_reason": "end_turn",
                },
                "timestamp": "2026-03-15T12:00:00Z",
            },
        ])

        _run_hook("no-turns", transcript, tmp_path)

        # No chain created (no turns extracted)
        chain_path = tmp_path / ".claudedeck" / "no-turns.chain.jsonl"
        assert not chain_path.exists()

    def test_hook_idempotent_on_same_transcript(self, tmp_path):
        """Running hook twice on same transcript doesn't duplicate records."""
        records = make_session_jsonl([
            ("prompt 1", "response 1", "model"),
            ("prompt 2", "response 2", "model"),
        ])
        transcript = tmp_path / "t.jsonl"
        _write_jsonl(transcript, records)

        # First run
        _run_hook("idem", transcript, tmp_path)
        chain1 = Chain.load(tmp_path / ".claudedeck" / "idem.chain.jsonl")
        assert len(chain1.records) == 2

        # Second run on same transcript
        _run_hook("idem", transcript, tmp_path)
        chain2 = Chain.load(tmp_path / ".claudedeck" / "idem.chain.jsonl")
        assert len(chain2.records) == 2, "No duplicates after second run"
