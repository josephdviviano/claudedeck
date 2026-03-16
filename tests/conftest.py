"""Shared fixtures for claudedeck tests."""

import json
import pytest
from pathlib import Path

from claudedeck.core import Chain


SAMPLE_TURNS = [
    ("Write a function to compute GC content", "Here's a function that computes GC content from a DNA sequence..."),
    ("Add error handling for invalid bases", "I've added validation that raises ValueError for non-ACGT characters."),
    ("What about RNA sequences?", "For RNA, you'd also accept U (uracil) instead of T (thymine)."),
]


@pytest.fixture
def chain_3turns():
    """A chain with 3 pre-populated turns."""
    chain = Chain()
    for prompt, response in SAMPLE_TURNS:
        chain.append_turn(prompt=prompt, response=response, model="test-model")
    return chain


@pytest.fixture
def chain_file(tmp_path, chain_3turns):
    """A chain saved to a temp JSONL file."""
    path = tmp_path / "test.chain.jsonl"
    chain_3turns.save(path)
    return path


@pytest.fixture
def vault_data():
    """Vault data matching SAMPLE_TURNS."""
    return {
        str(i): {"prompt": p, "response": r}
        for i, (p, r) in enumerate(SAMPLE_TURNS)
    }


@pytest.fixture
def vault_file(tmp_path, vault_data):
    """A vault JSON file matching SAMPLE_TURNS."""
    path = tmp_path / "test.vault.json"
    with open(path, "w") as f:
        json.dump(vault_data, f)
    return path


def make_session_jsonl(turns, session_id="test-session"):
    """Build a list of JSONL records simulating a Claude Code session.

    Args:
        turns: list of (prompt_text, response_text, model) tuples.
               response_text can be a string or list of content blocks.
    """
    records = []
    prev_uuid = None
    uuid_counter = 0

    for prompt_text, response_content, model in turns:
        uuid_counter += 1
        user_uuid = f"user-{uuid_counter:04d}"
        uuid_counter += 1
        assistant_uuid = f"asst-{uuid_counter:04d}"

        # User message
        records.append({
            "type": "user",
            "uuid": user_uuid,
            "parentUuid": prev_uuid,
            "promptId": f"prompt-{uuid_counter}",
            "message": {
                "role": "user",
                "content": prompt_text,
            },
            "timestamp": f"2026-03-15T12:{uuid_counter:02d}:00.000Z",
            "sessionId": session_id,
        })

        # Assistant message
        if isinstance(response_content, str):
            content_blocks = [{"type": "text", "text": response_content}]
        else:
            content_blocks = response_content

        records.append({
            "type": "assistant",
            "uuid": assistant_uuid,
            "parentUuid": user_uuid,
            "message": {
                "role": "assistant",
                "model": model,
                "content": content_blocks,
                "stop_reason": "end_turn",
            },
            "requestId": f"req_{uuid_counter:04d}",
            "timestamp": f"2026-03-15T12:{uuid_counter:02d}:05.000Z",
            "sessionId": session_id,
        })

        prev_uuid = assistant_uuid

    return records


def make_tool_use_session():
    """Build JSONL records for a session with tool use (multiple assistant messages per turn)."""
    records = []

    # User prompt
    records.append({
        "type": "user",
        "uuid": "user-0001",
        "parentUuid": None,
        "promptId": "prompt-1",
        "message": {"role": "user", "content": "Read my config file"},
        "timestamp": "2026-03-15T12:00:00.000Z",
        "sessionId": "tool-session",
    })

    # Assistant: tool_use (not end_turn)
    records.append({
        "type": "assistant",
        "uuid": "asst-0001",
        "parentUuid": "user-0001",
        "message": {
            "role": "assistant",
            "model": "claude-opus-4-6",
            "content": [
                {"type": "text", "text": "Let me read that file."},
                {"type": "tool_use", "id": "toolu_001", "name": "Read", "input": {"file_path": "/config.json"}},
            ],
            "stop_reason": None,
        },
        "requestId": "req_0001",
        "timestamp": "2026-03-15T12:00:05.000Z",
        "sessionId": "tool-session",
    })

    # Tool result (user message without promptId)
    records.append({
        "type": "user",
        "uuid": "user-0002",
        "parentUuid": "asst-0001",
        "message": {
            "role": "user",
            "content": [{"tool_use_id": "toolu_001", "type": "tool_result", "content": '{"key": "value"}'}],
        },
        "timestamp": "2026-03-15T12:00:06.000Z",
        "sessionId": "tool-session",
    })

    # Assistant: final response (end_turn)
    records.append({
        "type": "assistant",
        "uuid": "asst-0002",
        "parentUuid": "user-0002",
        "message": {
            "role": "assistant",
            "model": "claude-opus-4-6",
            "content": [{"type": "text", "text": "Your config has key=value."}],
            "stop_reason": "end_turn",
        },
        "requestId": "req_0002",
        "timestamp": "2026-03-15T12:00:10.000Z",
        "sessionId": "tool-session",
    })

    return records


def make_multi_tool_session():
    """Build JSONL records for a session with multiple tool calls in one turn."""
    records = []

    records.append({
        "type": "user",
        "uuid": "user-0001",
        "parentUuid": None,
        "promptId": "prompt-1",
        "message": {"role": "user", "content": "Read config and write output"},
        "timestamp": "2026-03-15T12:00:00.000Z",
        "sessionId": "multi-tool-session",
    })

    # Assistant: first tool call
    records.append({
        "type": "assistant",
        "uuid": "asst-0001",
        "parentUuid": "user-0001",
        "message": {
            "role": "assistant",
            "model": "claude-opus-4-6",
            "content": [
                {"type": "text", "text": "I'll read the config first."},
                {"type": "tool_use", "id": "toolu_001", "name": "Read",
                 "input": {"file_path": "/app/config.yaml"}},
            ],
            "stop_reason": None,
        },
        "requestId": "req_0001",
        "timestamp": "2026-03-15T12:00:01.000Z",
        "sessionId": "multi-tool-session",
    })

    # Tool result for Read
    records.append({
        "type": "user",
        "uuid": "user-0002",
        "parentUuid": "asst-0001",
        "message": {
            "role": "user",
            "content": [{"tool_use_id": "toolu_001", "type": "tool_result",
                         "content": "db_host: localhost\ndb_port: 5432"}],
        },
        "timestamp": "2026-03-15T12:00:02.000Z",
        "sessionId": "multi-tool-session",
    })

    # Assistant: second tool call
    records.append({
        "type": "assistant",
        "uuid": "asst-0002",
        "parentUuid": "user-0002",
        "message": {
            "role": "assistant",
            "model": "claude-opus-4-6",
            "content": [
                {"type": "tool_use", "id": "toolu_002", "name": "Write",
                 "input": {"file_path": "/app/output.txt", "content": "Config loaded."}},
            ],
            "stop_reason": None,
        },
        "requestId": "req_0002",
        "timestamp": "2026-03-15T12:00:03.000Z",
        "sessionId": "multi-tool-session",
    })

    # Tool result for Write
    records.append({
        "type": "user",
        "uuid": "user-0003",
        "parentUuid": "asst-0002",
        "message": {
            "role": "user",
            "content": [{"tool_use_id": "toolu_002", "type": "tool_result",
                         "content": "File written successfully."}],
        },
        "timestamp": "2026-03-15T12:00:04.000Z",
        "sessionId": "multi-tool-session",
    })

    # Assistant: final response
    records.append({
        "type": "assistant",
        "uuid": "asst-0003",
        "parentUuid": "user-0003",
        "message": {
            "role": "assistant",
            "model": "claude-opus-4-6",
            "content": [{"type": "text", "text": "Done! Config read and output written."}],
            "stop_reason": "end_turn",
        },
        "requestId": "req_0003",
        "timestamp": "2026-03-15T12:00:05.000Z",
        "sessionId": "multi-tool-session",
    })

    return records
