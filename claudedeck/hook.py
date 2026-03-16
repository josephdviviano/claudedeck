#!/usr/bin/env python3
"""
claudedeck.hook — Claude Code Stop hook for building hash chains.

Called by Claude Code after each assistant response. Reads the session
JSONL transcript, finds new turns since the last chain record, and
appends them to the hash chain.

Receives JSON on stdin from Claude Code:
    {"session_id": "...", "transcript_path": "...", "cwd": "...", ...}

Chain and vault files are stored in .claudedeck/ within the project root.
"""

import json
import sys
import os
from pathlib import Path

from claudedeck.core import Chain


# ---------------------------------------------------------------------------
# JSONL parsing
# ---------------------------------------------------------------------------

def read_jsonl(path: str) -> list[dict]:
    """Read all lines from a JSONL file."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def extract_turns(records: list[dict]) -> list[dict]:
    """Extract human→assistant turns from a session JSONL.

    A 'turn' is a user prompt (type=user with a promptId, i.e. a real
    human message, not a tool_result relay) followed by the final
    assistant response before the next human prompt.

    Returns a list of dicts with keys:
        prompt, response, model, request_id, timestamp, prompt_uuid
    """
    # Collect user prompts (real human messages have a promptId field)
    user_msgs = []
    assistant_msgs = []

    for rec in records:
        if rec.get("type") == "user" and rec.get("promptId"):
            user_msgs.append(rec)
        elif rec.get("type") == "assistant":
            assistant_msgs.append(rec)

    # For each user prompt, walk the parentUuid chain to find the final
    # assistant response (the one with stop_reason == "end_turn")
    turns = []
    for i, user_msg in enumerate(user_msgs):
        prompt_text = _extract_prompt_text(user_msg)
        prompt_uuid = user_msg["uuid"]

        # Find all assistant messages that are descendants of this user msg.
        # The final one (with end_turn) is the response we want.
        # Simple approach: find the last assistant message before the next
        # user prompt that links back through the parentUuid chain.
        final_assistant = _find_final_response(
            prompt_uuid, records,
            next_prompt_uuid=user_msgs[i + 1]["uuid"] if i + 1 < len(user_msgs) else None,
        )

        if final_assistant is None:
            continue

        response_text = _flatten_assistant_content(final_assistant)
        model = final_assistant.get("message", {}).get("model", "unknown")
        request_id = final_assistant.get("requestId")
        timestamp = final_assistant.get("timestamp", "")

        turns.append({
            "prompt": prompt_text,
            "response": response_text,
            "model": model,
            "request_id": request_id,
            "timestamp": timestamp,
            "prompt_uuid": prompt_uuid,
        })

    return turns


def _extract_prompt_text(user_msg: dict) -> str:
    """Extract the human's prompt text from a user record."""
    content = user_msg.get("message", {}).get("content", "")
    if isinstance(content, str):
        return content
    # Array of content blocks — extract text blocks only
    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block["text"])
        elif isinstance(block, str):
            parts.append(block)
    return "\n".join(parts) if parts else ""


def _find_final_response(
    prompt_uuid: str,
    all_records: list[dict],
    next_prompt_uuid: str | None,
) -> dict | None:
    """Find the final assistant response for a given user prompt.

    The final response is the last assistant message with stop_reason="end_turn"
    that appears between this prompt and the next one in the transcript.
    """
    # Find index range in all_records
    start_idx = None
    end_idx = len(all_records)
    for i, rec in enumerate(all_records):
        if rec.get("uuid") == prompt_uuid:
            start_idx = i
        if next_prompt_uuid and rec.get("uuid") == next_prompt_uuid:
            end_idx = i
            break

    if start_idx is None:
        return None

    # Find the last assistant message with end_turn in this range
    best = None
    for rec in all_records[start_idx:end_idx]:
        if rec.get("type") == "assistant":
            stop = rec.get("message", {}).get("stop_reason")
            if stop == "end_turn":
                best = rec

    # If no end_turn found, take the last assistant message in range
    if best is None:
        for rec in reversed(all_records[start_idx:end_idx]):
            if rec.get("type") == "assistant":
                best = rec
                break

    return best


def _flatten_assistant_content(assistant_msg: dict) -> str:
    """Flatten an assistant message's content blocks into a single string.

    Text blocks are concatenated. Tool use blocks are represented as
    [tool_use: ToolName] markers so the chain captures that a tool was
    called without including the full tool input/output (which is in
    separate records).
    """
    content = assistant_msg.get("message", {}).get("content", [])
    parts = []
    for block in content:
        if isinstance(block, dict):
            if block.get("type") == "text":
                parts.append(block["text"])
            elif block.get("type") == "tool_use":
                parts.append(f"[tool_use: {block.get('name', 'unknown')}]")
    return "\n".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def get_deck_dir(cwd: str) -> Path:
    """Get or create the .claudedeck directory for this project."""
    deck_dir = Path(cwd) / ".claudedeck"
    deck_dir.mkdir(exist_ok=True)
    return deck_dir


def load_state(deck_dir: Path, session_id: str) -> dict:
    """Load hook state (tracks which turns have been chained)."""
    state_path = deck_dir / f"{session_id}.state.json"
    if state_path.exists():
        with open(state_path) as f:
            return json.load(f)
    return {"chained_count": 0}


def save_state(deck_dir: Path, session_id: str, state: dict):
    state_path = deck_dir / f"{session_id}.state.json"
    with open(state_path, "w") as f:
        json.dump(state, f)


# ---------------------------------------------------------------------------
# Vault (simple JSON — same as prototype)
# ---------------------------------------------------------------------------

def load_vault(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_vault(path: Path, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=True)


# ---------------------------------------------------------------------------
# Main hook entry point
# ---------------------------------------------------------------------------

def main():
    # Read hook input from stdin
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        # Not a valid hook invocation — exit silently
        return

    session_id = hook_input.get("session_id", "")
    transcript_path = hook_input.get("transcript_path", "")
    cwd = hook_input.get("cwd", os.getcwd())

    if not transcript_path or not Path(transcript_path).exists():
        return

    # Set up paths
    deck_dir = get_deck_dir(cwd)
    chain_path = deck_dir / f"{session_id}.chain.jsonl"
    vault_path = deck_dir / f"{session_id}.vault.json"

    # Load existing chain + state
    if chain_path.exists():
        chain = Chain.load(chain_path)
    else:
        chain = Chain()

    state = load_state(deck_dir, session_id)
    vault_data = load_vault(vault_path)

    # Parse transcript and extract turns
    records = read_jsonl(transcript_path)
    turns = extract_turns(records)

    # Find new turns (ones we haven't chained yet)
    chained_count = state.get("chained_count", 0)
    new_turns = turns[chained_count:]

    if not new_turns:
        return

    # Append new turns to the chain
    for turn in new_turns:
        record = chain.append_turn(
            prompt=turn["prompt"],
            response=turn["response"],
            model=turn["model"],
            api_request_id=turn.get("request_id"),
        )

        # Store plaintext in vault
        vault_data[str(record.seq)] = {
            "prompt": turn["prompt"],
            "response": turn["response"],
            "model": turn["model"],
            "timestamp": turn["timestamp"],
        }

    # Save everything
    chain.save(chain_path)
    save_vault(vault_path, vault_data)
    save_state(deck_dir, session_id, {"chained_count": len(turns)})

    # Print status to stderr (visible in Claude Code's hook output)
    n = len(new_turns)
    print(
        f"claudedeck: +{n} turn{'s' if n != 1 else ''} chained "
        f"(seq {chain.records[-1].seq}, head={chain.head_hash[:12]}...)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
