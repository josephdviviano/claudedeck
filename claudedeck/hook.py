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

from claudedeck.core import Chain, ArtifactRef, sha256_file, file_lock
from claudedeck.snapshot import FileSnapshot


# ---------------------------------------------------------------------------
# JSONL parsing
# ---------------------------------------------------------------------------

def read_jsonl(path: str) -> list[dict]:
    """Read all lines from a JSONL file, skipping malformed lines."""
    records = []
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(
                    f"claudedeck: WARNING: skipping malformed line {line_num} "
                    f"in {path}: {e}",
                    file=sys.stderr,
                )
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
        next_prompt_uuid = user_msgs[i + 1]["uuid"] if i + 1 < len(user_msgs) else None

        # Find all assistant messages that are descendants of this user msg.
        # The final one (with end_turn) is the response we want.
        final_assistant = _find_final_response(
            prompt_uuid, records,
            next_prompt_uuid=next_prompt_uuid,
        )

        if final_assistant is None:
            continue

        response_text = _flatten_assistant_content(final_assistant)
        model = final_assistant.get("message", {}).get("model", "unknown")
        request_id = final_assistant.get("requestId")
        timestamp = final_assistant.get("timestamp", "")

        # Extract tool calls from all assistant messages in this turn
        tool_calls_in_turn = extract_tool_calls(records, prompt_uuid, next_prompt_uuid)
        file_ops = extract_file_operations(tool_calls_in_turn)
        tool_names = get_tool_names(tool_calls_in_turn)

        turns.append({
            "prompt": prompt_text,
            "response": response_text,
            "model": model,
            "request_id": request_id,
            "timestamp": timestamp,
            "prompt_uuid": prompt_uuid,
            "tool_calls": tool_names,
            "file_operations": file_ops,
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
# Tool call extraction
# ---------------------------------------------------------------------------

# Tools that modify the filesystem
FILE_WRITE_TOOLS = {"Write", "Edit"}
FILE_EXEC_TOOLS = {"Bash"}


def extract_tool_calls(
    all_records: list[dict],
    prompt_uuid: str,
    next_prompt_uuid: str | None,
) -> list[dict]:
    """Extract all tool_use blocks from assistant messages within a turn.

    Walks ALL assistant messages between the user prompt and the next prompt,
    collecting every tool_use content block.

    Returns list of dicts: {name, id, input}
    """
    start_idx = None
    end_idx = len(all_records)
    for i, rec in enumerate(all_records):
        if rec.get("uuid") == prompt_uuid:
            start_idx = i
        if next_prompt_uuid and rec.get("uuid") == next_prompt_uuid:
            end_idx = i
            break

    if start_idx is None:
        return []

    tool_calls = []
    for rec in all_records[start_idx:end_idx]:
        if rec.get("type") != "assistant":
            continue
        content = rec.get("message", {}).get("content", [])
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_calls.append({
                    "name": block.get("name", "unknown"),
                    "id": block.get("id"),
                    "input": block.get("input", {}),
                })
    return tool_calls


def extract_file_operations(tool_calls: list[dict]) -> list[dict]:
    """Identify file-modifying tool calls and extract their targets.

    Returns list of: {tool_name, tool_id, file_path, operation}
    where operation is "create" (Write), "modify" (Edit), or "execute" (Bash).
    """
    ops = []
    for tc in tool_calls:
        name = tc["name"]
        if name in FILE_WRITE_TOOLS:
            file_path = tc["input"].get("file_path")
            if file_path:
                ops.append({
                    "tool_name": name,
                    "tool_id": tc["id"],
                    "file_path": file_path,
                    "operation": "create" if name == "Write" else "modify",
                })
        elif name in FILE_EXEC_TOOLS:
            ops.append({
                "tool_name": name,
                "tool_id": tc["id"],
                "file_path": None,  # Bash targets are unknown
                "operation": "execute",
                "command": tc["input"].get("command", ""),
            })
    return ops


def get_tool_names(tool_calls: list[dict]) -> list[str]:
    """Extract unique tool names from tool_calls list."""
    seen = []
    for tc in tool_calls:
        name = tc["name"]
        if name not in seen:
            seen.append(name)
    return seen


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def get_deck_dir(cwd: str) -> Path:
    """Get or create the .claudedeck directory for this project."""
    deck_dir = Path(cwd) / ".claudedeck"
    deck_dir.mkdir(exist_ok=True)
    return deck_dir


def load_state(deck_dir: Path, session_id: str) -> dict:
    """Load hook state (tracks which turns have been chained).

    Verifies HMAC if present. On mismatch, warns and resets state.
    """
    state_path = deck_dir / f"{session_id}.state.json"
    if not state_path.exists():
        return {"chained_count": 0}
    try:
        with open(state_path) as f:
            state = json.load(f)
    except (json.JSONDecodeError, ValueError):
        return {"chained_count": 0}

    stored_hmac = state.pop("_hmac", None)
    if stored_hmac is not None:
        try:
            from claudedeck.integrity import verify_hmac_json
            if not verify_hmac_json(state, stored_hmac, deck_dir):
                print(
                    "claudedeck: WARNING: state file HMAC mismatch — "
                    "file may have been tampered with. Resetting state.",
                    file=sys.stderr,
                )
                return {"chained_count": 0}
        except Exception:
            pass  # graceful degradation if key missing
    return state


def save_state(deck_dir: Path, session_id: str, state: dict):
    from claudedeck.core import atomic_write
    state_path = deck_dir / f"{session_id}.state.json"
    state_copy = {k: v for k, v in state.items() if k != "_hmac"}
    try:
        from claudedeck.integrity import hmac_json
        state_copy["_hmac"] = hmac_json(state_copy, deck_dir)
    except Exception:
        pass  # graceful fallback if key not yet created
    atomic_write(state_path, json.dumps(state_copy))


# ---------------------------------------------------------------------------
# Vault (simple JSON — same as prototype)
# ---------------------------------------------------------------------------

def load_vault(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_vault(path: Path, data: dict):
    from claudedeck.core import atomic_write
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=True))


# ---------------------------------------------------------------------------
# Main hook entry point
# ---------------------------------------------------------------------------

def attribute_snapshot_changes(
    snapshot_diff,
    tool_artifacts: list[ArtifactRef],
    tool_calls: list[str],
    cwd: str,
) -> list[ArtifactRef]:
    """Cross-reference snapshot diff with tool-call artifacts to find additional changes.

    Files already tracked by Layer 1 (Write/Edit tool calls) are skipped.
    Remaining changed files get:
      - "claude:Bash(inferred)" if Bash was called in the turn
      - "unattributed" otherwise (likely user change between turns)

    Returns ArtifactRefs for newly discovered changes only.
    """
    # Build set of files already attributed by Layer 1 (prefer filepath, fall back to filename)
    already_tracked = {a.filepath or a.filename for a in tool_artifacts}

    root = Path(cwd).resolve()
    extra_artifacts = []

    for rel_path, _new_hash in snapshot_diff.changed_files.items():
        full_path = root / rel_path

        # Skip if already covered by a Write/Edit tool call (check both filepath and filename)
        if rel_path in already_tracked or full_path.name in already_tracked:
            continue

        if not full_path.is_file():
            continue

        attribution = "claude:Bash(inferred)" if "Bash" in tool_calls else "unattributed"

        try:
            extra_artifacts.append(ArtifactRef.from_file(
                full_path,
                attribution=attribution,
                project_root=cwd,
            ))
        except (OSError, PermissionError):
            continue

    return extra_artifacts


def _create_artifacts_from_ops(
    file_ops: list[dict], cwd: str, project_root: str | None = None,
) -> list[ArtifactRef]:
    """Create ArtifactRefs from file operations (Write/Edit tool calls).

    Only creates refs for files that exist on disk. Bash operations are
    handled separately by the snapshot diff (Phase 2).
    """
    artifacts = []
    seen_paths = set()

    for op in file_ops:
        file_path = op.get("file_path")
        if not file_path or op["operation"] == "execute":
            continue

        # Resolve relative paths against cwd
        p = Path(file_path)
        if not p.is_absolute():
            p = Path(cwd) / p

        # Skip if file doesn't exist (was deleted or path is wrong)
        if not p.exists() or not p.is_file():
            continue

        # Deduplicate (same file may be Write'd then Edit'd in one turn)
        resolved = str(p.resolve())
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)

        attribution = f"claude:{op['tool_name']}"
        try:
            artifacts.append(ArtifactRef.from_file(
                p,
                attribution=attribution,
                source_tool_id=op.get("tool_id"),
                project_root=project_root,
            ))
        except (OSError, PermissionError):
            continue

    return artifacts


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

    # Acquire exclusive lock for the entire session to prevent concurrent corruption
    with file_lock(deck_dir / f"{session_id}"):
        # Load existing chain + state
        if chain_path.exists():
            chain = Chain.load(chain_path)
        else:
            chain = Chain()

        state = load_state(deck_dir, session_id)
        vault_data = load_vault(vault_path)

        # Load previous filesystem snapshot (for change detection)
        prev_snapshot_data = state.get("snapshot")
        prev_snapshot = FileSnapshot.from_dict(prev_snapshot_data) if prev_snapshot_data else None

        # Parse transcript and extract turns
        records = read_jsonl(transcript_path)
        turns = extract_turns(records)

        # Find new turns (ones we haven't chained yet)
        chained_count = state.get("chained_count", 0)
        new_turns = turns[chained_count:]

        if not new_turns:
            # Still capture a snapshot even if no new turns, so next run has a baseline
            if prev_snapshot is None:
                current_snapshot = FileSnapshot.capture(Path(cwd))
                save_state(deck_dir, session_id, {
                    "chained_count": chained_count,
                    "snapshot": current_snapshot.to_dict(),
                })
            return

        # Capture current filesystem snapshot
        current_snapshot = FileSnapshot.capture(Path(cwd))

        # Append new turns to the chain
        for turn in new_turns:
            # Layer 1: Create ArtifactRefs from file operations (Write/Edit tool calls)
            tool_artifacts = _create_artifacts_from_ops(
                turn.get("file_operations", []), cwd, project_root=cwd,
            )

            # Layer 2: Cross-reference snapshot diff for additional changes
            snapshot_artifacts = []
            if prev_snapshot is not None:
                diff = prev_snapshot.diff(current_snapshot)
                if not diff.is_empty:
                    snapshot_artifacts = attribute_snapshot_changes(
                        diff,
                        tool_artifacts,
                        turn.get("tool_calls", []),
                        cwd,
                    )

            artifacts = tool_artifacts + snapshot_artifacts

            record = chain.append_turn(
                prompt=turn["prompt"],
                response=turn["response"],
                artifacts=artifacts,
                tool_calls=turn.get("tool_calls", []),
                model=turn["model"],
                api_request_id=turn.get("request_id"),
            )

            # Store plaintext in vault
            vault_entry = {
                "prompt": turn["prompt"],
                "response": turn["response"],
                "model": turn["model"],
                "timestamp": turn["timestamp"],
            }
            if turn.get("file_operations"):
                vault_entry["file_operations"] = turn["file_operations"]
            vault_data[str(record.seq)] = vault_entry

        # Save everything
        chain.save(chain_path)
        save_vault(vault_path, vault_data)
        save_state(deck_dir, session_id, {
            "chained_count": len(turns),
            "snapshot": current_snapshot.to_dict(),
        })

    # Print status to stderr (visible in Claude Code's hook output)
    n = len(new_turns)
    print(
        f"claudedeck: +{n} turn{'s' if n != 1 else ''} chained "
        f"(seq {chain.records[-1].seq}, head={chain.head_hash[:12]}...)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
