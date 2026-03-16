"""Tests for claudedeck.hook — JSONL parsing, turn extraction, and hook behavior."""

import json
import pytest
from unittest.mock import patch
from io import StringIO
from pathlib import Path

from claudedeck.hook import (
    extract_turns,
    _extract_prompt_text,
    _flatten_assistant_content,
    read_jsonl,
    load_state,
    save_state,
    load_vault,
    save_vault,
)
from claudedeck.core import Chain
from tests.conftest import make_session_jsonl, make_tool_use_session


# ---------------------------------------------------------------------------
# Turn extraction
# ---------------------------------------------------------------------------

class TestExtractTurns:
    def test_simple_single_turn(self):
        records = make_session_jsonl([
            ("hello", "world", "test-model"),
        ])
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["prompt"] == "hello"
        assert turns[0]["response"] == "world"
        assert turns[0]["model"] == "test-model"

    def test_multi_turn(self):
        records = make_session_jsonl([
            ("first", "response one", "model-a"),
            ("second", "response two", "model-b"),
            ("third", "response three", "model-c"),
        ])
        turns = extract_turns(records)
        assert len(turns) == 3
        assert turns[0]["prompt"] == "first"
        assert turns[1]["prompt"] == "second"
        assert turns[2]["prompt"] == "third"

    def test_tool_use_session(self):
        """Tool use creates multiple assistant messages — only the final (end_turn) should be the response."""
        records = make_tool_use_session()
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["prompt"] == "Read my config file"
        assert turns[0]["response"] == "Your config has key=value."

    def test_skips_tool_result_users(self):
        """User records without promptId (tool_result relays) should not be counted as turns."""
        records = make_tool_use_session()
        # Count user records with promptId
        user_prompts = [r for r in records if r.get("type") == "user" and r.get("promptId")]
        assert len(user_prompts) == 1  # Only the real human prompt

    def test_request_id_captured(self):
        records = make_session_jsonl([("q", "a", "model")])
        turns = extract_turns(records)
        assert turns[0]["request_id"] is not None

    def test_empty_records(self):
        assert extract_turns([]) == []

    def test_no_assistant_response(self):
        """If there's a user prompt but no assistant response, the turn is skipped."""
        records = [{
            "type": "user",
            "uuid": "u1",
            "parentUuid": None,
            "promptId": "p1",
            "message": {"role": "user", "content": "hello"},
            "timestamp": "2026-03-15T12:00:00.000Z",
            "sessionId": "test",
        }]
        turns = extract_turns(records)
        assert len(turns) == 0


# ---------------------------------------------------------------------------
# Content extraction helpers
# ---------------------------------------------------------------------------

class TestContentExtraction:
    def test_prompt_text_string(self):
        msg = {"message": {"content": "hello world"}}
        assert _extract_prompt_text(msg) == "hello world"

    def test_prompt_text_blocks(self):
        msg = {"message": {"content": [
            {"type": "text", "text": "part one"},
            {"type": "text", "text": "part two"},
        ]}}
        assert _extract_prompt_text(msg) == "part one\npart two"

    def test_prompt_text_ignores_tool_results(self):
        msg = {"message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "result"},
        ]}}
        assert _extract_prompt_text(msg) == ""

    def test_flatten_text_only(self):
        msg = {"message": {"content": [
            {"type": "text", "text": "Hello!"},
            {"type": "text", "text": "How are you?"},
        ]}}
        result = _flatten_assistant_content(msg)
        assert "Hello!" in result
        assert "How are you?" in result

    def test_flatten_tool_use(self):
        msg = {"message": {"content": [
            {"type": "text", "text": "Let me check."},
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {}},
        ]}}
        result = _flatten_assistant_content(msg)
        assert "Let me check." in result
        assert "[tool_use: Read]" in result

    def test_flatten_empty_content(self):
        msg = {"message": {"content": []}}
        assert _flatten_assistant_content(msg) == ""


# ---------------------------------------------------------------------------
# Hook state and idempotency
# ---------------------------------------------------------------------------

class TestHookState:
    def test_state_roundtrip(self, tmp_path):
        save_state(tmp_path, "sess-1", {"chained_count": 5})
        state = load_state(tmp_path, "sess-1")
        assert state["chained_count"] == 5

    def test_state_default(self, tmp_path):
        state = load_state(tmp_path, "nonexistent")
        assert state == {"chained_count": 0}

    def test_vault_roundtrip(self, tmp_path):
        path = tmp_path / "vault.json"
        data = {"0": {"prompt": "hi", "response": "hey"}}
        save_vault(path, data)
        loaded = load_vault(path)
        assert loaded == data

    def test_vault_default(self, tmp_path):
        assert load_vault(tmp_path / "nope.json") == {}


class TestHookIdempotency:
    def _write_jsonl(self, path, records):
        with open(path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def test_no_duplicate_records(self, tmp_path):
        """Running the hook twice on the same transcript should not create duplicates."""
        records = make_session_jsonl([
            ("hello", "world", "test-model"),
        ])
        transcript = tmp_path / "transcript.jsonl"
        self._write_jsonl(transcript, records)

        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        session_id = "test-session"

        # First run
        self._run_hook_logic(transcript, deck_dir, session_id)
        chain1 = Chain.load(deck_dir / f"{session_id}.chain.jsonl")
        assert len(chain1.records) == 1

        # Second run — should be a no-op
        self._run_hook_logic(transcript, deck_dir, session_id)
        chain2 = Chain.load(deck_dir / f"{session_id}.chain.jsonl")
        assert len(chain2.records) == 1

    def test_incremental_chaining(self, tmp_path):
        """Adding a new turn to the transcript should chain only the new turn."""
        turn1 = make_session_jsonl([("first", "one", "model")])
        transcript = tmp_path / "transcript.jsonl"
        self._write_jsonl(transcript, turn1)

        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        session_id = "test-session"

        # First run: 1 turn
        self._run_hook_logic(transcript, deck_dir, session_id)
        chain = Chain.load(deck_dir / f"{session_id}.chain.jsonl")
        assert len(chain.records) == 1

        # Add a second turn
        turns_2 = make_session_jsonl([("first", "one", "model"), ("second", "two", "model")])
        self._write_jsonl(transcript, turns_2)

        # Second run: should chain only the new turn
        self._run_hook_logic(transcript, deck_dir, session_id)
        chain = Chain.load(deck_dir / f"{session_id}.chain.jsonl")
        assert len(chain.records) == 2

        # Chain should still verify
        valid, errors = chain.verify()
        assert valid is True

    def _run_hook_logic(self, transcript_path, deck_dir, session_id):
        """Replicate the hook's main logic without stdin."""
        from claudedeck.hook import extract_turns, load_state, save_state, load_vault, save_vault

        chain_path = deck_dir / f"{session_id}.chain.jsonl"
        vault_path = deck_dir / f"{session_id}.vault.json"

        if chain_path.exists():
            chain = Chain.load(chain_path)
        else:
            chain = Chain()

        state = load_state(deck_dir, session_id)
        vault_data = load_vault(vault_path)

        records = read_jsonl(str(transcript_path))
        turns = extract_turns(records)

        chained_count = state.get("chained_count", 0)
        new_turns = turns[chained_count:]

        for turn in new_turns:
            record = chain.append_turn(
                prompt=turn["prompt"],
                response=turn["response"],
                model=turn["model"],
                api_request_id=turn.get("request_id"),
            )
            vault_data[str(record.seq)] = {
                "prompt": turn["prompt"],
                "response": turn["response"],
            }

        chain.save(chain_path)
        save_vault(vault_path, vault_data)
        save_state(deck_dir, session_id, {"chained_count": len(turns)})
