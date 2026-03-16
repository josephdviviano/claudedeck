#!/usr/bin/env python3
"""
claudedeck — Verifiable Claude Code sessions.

Usage:
    python -m claudedeck on                 # enable verification for this project
    python -m claudedeck off                # disable verification
    python -m claudedeck status             # show current state
    python -m claudedeck verify [SESSION]   # verify chain integrity
    python -m claudedeck inspect [SESSION]  # inspect chain records
    python -m claudedeck proof [SESSION]    # generate proof bundle
    python -m claudedeck session            # interactive REPL (legacy)
"""

import argparse
import json
import sys
from pathlib import Path

from claudedeck.core import Chain
from claudedeck.settings import (
    find_project_root,
    get_settings_path,
    read_settings,
    write_settings,
    is_hook_installed,
    install_hook,
    remove_hook,
)


def format_hash(h: str, length: int = 12) -> str:
    return h[:length] + "..."


def get_deck_dir(project_root: Path) -> Path:
    return project_root / ".claudedeck"


def list_sessions(deck_dir: Path) -> list[str]:
    """List all session IDs that have chain files."""
    if not deck_dir.exists():
        return []
    return sorted(
        p.stem.replace(".chain", "")
        for p in deck_dir.glob("*.chain.jsonl")
    )


def most_recent_session(deck_dir: Path) -> str | None:
    """Return the most recently modified session ID."""
    if not deck_dir.exists():
        return None
    chains = sorted(deck_dir.glob("*.chain.jsonl"), key=lambda p: p.stat().st_mtime)
    if not chains:
        return None
    return chains[-1].stem.replace(".chain", "")


def resolve_session(args, deck_dir: Path) -> str | None:
    """Resolve a session ID from args or pick the most recent."""
    sid = getattr(args, "session", None)
    if sid:
        return sid
    return most_recent_session(deck_dir)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_on(args):
    """Enable claudedeck verification for this project."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory (no .git/ or .claude/ found)")
        sys.exit(1)

    settings_path = get_settings_path(root)
    settings = read_settings(settings_path)

    if is_hook_installed(settings):
        print("claudedeck is already enabled for this project.")
        return

    settings = install_hook(settings)
    write_settings(settings_path, settings)

    # Ensure .claudedeck/ exists
    get_deck_dir(root).mkdir(exist_ok=True)

    print("claudedeck enabled.")
    print(f"  hook installed in {settings_path.relative_to(root)}")
    print(f"  chain data will be stored in .claudedeck/")
    print()
    print("Start a claude session normally — each turn will be")
    print("automatically chained and verified.")


def cmd_off(args):
    """Disable claudedeck verification for this project."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    settings_path = get_settings_path(root)
    settings = read_settings(settings_path)

    if not is_hook_installed(settings):
        print("claudedeck is not currently enabled.")
        return

    settings = remove_hook(settings)
    write_settings(settings_path, settings)
    print("claudedeck disabled. Chain data in .claudedeck/ is preserved.")


def cmd_status(args):
    """Show claudedeck status for this project."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    settings_path = get_settings_path(root)
    settings = read_settings(settings_path)
    enabled = is_hook_installed(settings)

    print(f"claudedeck: {'ENABLED' if enabled else 'DISABLED'}")
    print(f"  project: {root}")

    deck_dir = get_deck_dir(root)
    sessions = list_sessions(deck_dir)

    if not sessions:
        print("  sessions: (none)")
        return

    print(f"  sessions: {len(sessions)}")
    print()

    for sid in sessions:
        chain_path = deck_dir / f"{sid}.chain.jsonl"
        chain = Chain.load(chain_path)
        valid, errors = chain.verify()

        vault_path = deck_dir / f"{sid}.vault.json"
        has_vault = vault_path.exists()

        status = "VALID" if valid else "INVALID"
        print(f"  {sid}")
        print(f"    turns: {len(chain.records)}  integrity: {status}  vault: {'yes' if has_vault else 'no'}")
        if chain.records:
            print(f"    head:  {format_hash(chain.head_hash, 24)}")
        if errors:
            for e in errors:
                print(f"    ERROR: {e}")


def cmd_verify(args):
    """Verify chain integrity."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    deck_dir = get_deck_dir(root)
    sid = resolve_session(args, deck_dir)

    if sid is None:
        print("No sessions found in .claudedeck/")
        sys.exit(1)

    chain_path = deck_dir / f"{sid}.chain.jsonl"
    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        sys.exit(1)

    chain = Chain.load(chain_path)
    valid, errors = chain.verify()

    print(f"Session: {sid}")
    print(f"Records: {len(chain.records)}")

    if valid:
        print(f"Chain integrity: VALID")
        print(f"  All {len(chain.records)} records internally consistent and linked")
        if chain.records:
            print(f"  Genesis: {format_hash(chain.records[0].record_hash, 24)}")
            print(f"  Head:    {format_hash(chain.head_hash, 24)}")
    else:
        print(f"Chain integrity: INVALID")
        for e in errors:
            print(f"  FAIL: {e}")
        sys.exit(1)

    # Cross-check vault if present
    vault_path = deck_dir / f"{sid}.vault.json"
    if vault_path.exists():
        from claudedeck.core import sha256_hex
        with open(vault_path) as f:
            vault_data = json.load(f)

        mismatches = []
        for seq_str, entry in vault_data.items():
            seq = int(seq_str)
            if seq >= len(chain.records):
                mismatches.append(f"Vault seq {seq} has no chain record")
                continue
            rec = chain.records[seq]
            prompt_hash = sha256_hex(entry["prompt"].encode("utf-8"))
            response_hash = sha256_hex(entry["response"].encode("utf-8"))
            if prompt_hash != rec.turn.prompt_hash:
                mismatches.append(f"Seq {seq}: vault prompt doesn't match chain hash")
            if response_hash != rec.turn.response_hash:
                mismatches.append(f"Seq {seq}: vault response doesn't match chain hash")

        if mismatches:
            print(f"\nVault cross-check: FAILED")
            for m in mismatches:
                print(f"  {m}")
            sys.exit(1)
        else:
            print(f"\nVault cross-check: PASSED ({len(vault_data)} entries match chain)")


def cmd_inspect(args):
    """Inspect chain records in detail."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    deck_dir = get_deck_dir(root)
    sid = resolve_session(args, deck_dir)

    if sid is None:
        print("No sessions found in .claudedeck/")
        sys.exit(1)

    chain_path = deck_dir / f"{sid}.chain.jsonl"
    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        sys.exit(1)

    chain = Chain.load(chain_path)
    vault_path = deck_dir / f"{sid}.vault.json"
    vault_data = {}
    if vault_path.exists():
        with open(vault_path) as f:
            vault_data = json.load(f)

    print(f"Session: {sid}")
    print(f"Records: {len(chain.records)}")
    if chain.records:
        print(f"Head:    {chain.head_hash}")
    print()

    for rec in chain.records:
        print(f"--- seq {rec.seq} ---")
        print(f"  hash:      {rec.record_hash}")
        print(f"  prev:      {rec.prev_hash}")
        print(f"  nonce:     {format_hash(rec.nonce, 16)}")
        print(f"  timestamp: {rec.timestamp}")
        if rec.turn.model:
            print(f"  model:     {rec.turn.model}")
        if rec.turn.api_request_id:
            print(f"  request:   {rec.turn.api_request_id}")
        if rec.turn.artifacts:
            for a in rec.turn.artifacts:
                print(f"  artifact:  {a.filename} ({a.size_bytes} bytes, {format_hash(a.sha256, 16)})")

        # Show plaintext preview from vault if available
        entry = vault_data.get(str(rec.seq))
        if entry:
            prompt = entry.get("prompt", "")
            response = entry.get("response", "")
            print(f"  prompt:    {prompt[:80]}{'...' if len(prompt) > 80 else ''}")
            print(f"  response:  {response[:80]}{'...' if len(response) > 80 else ''}")
        else:
            print(f"  prompt:    (hash only: {format_hash(rec.turn.prompt_hash, 16)})")
            print(f"  response:  (hash only: {format_hash(rec.turn.response_hash, 16)})")
        print()


def cmd_show(args):
    """Show the full conversation from a session."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    deck_dir = get_deck_dir(root)
    sid = resolve_session(args, deck_dir)

    if sid is None:
        print("No sessions found in .claudedeck/")
        sys.exit(1)

    chain_path = deck_dir / f"{sid}.chain.jsonl"
    vault_path = deck_dir / f"{sid}.vault.json"

    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        sys.exit(1)

    chain = Chain.load(chain_path)

    if not vault_path.exists():
        print("Vault not found — only hashes available (use 'inspect' instead)")
        sys.exit(1)

    with open(vault_path) as f:
        vault_data = json.load(f)

    # Group records into logical exchanges.
    # An "exchange" starts with a user prompt (non-empty prompt that isn't
    # just a tool_result relay) and includes all subsequent tool-use steps
    # until the next user prompt.
    exchanges = _group_exchanges(chain.records, vault_data)

    # Filter by seq range if requested
    if args.seq is not None:
        exchanges = [ex for ex in exchanges if ex["start_seq"] == args.seq]
        if not exchanges:
            print(f"No exchange starting at seq {args.seq}")
            sys.exit(1)

    # Header
    valid, _ = chain.verify()
    print(f"Session: {sid}")
    print(f"Chain:   {len(chain.records)} records, {'VALID' if valid else 'INVALID'}")
    print(f"Exchanges: {len(exchanges) if not args.seq else '(filtered)'}")
    print()

    for ex in exchanges:
        _print_exchange(ex, verbose=args.verbose)


def _group_exchanges(records, vault_data):
    """Group chain records into logical exchanges.

    An exchange is a user prompt followed by all the tool-use steps and
    the final text response. This collapses the many intermediate
    tool_use records into a single readable block.
    """
    exchanges = []
    current = None

    for rec in records:
        entry = vault_data.get(str(rec.seq), {})
        prompt = entry.get("prompt", "")
        response = entry.get("response", "")
        is_tool_use = response.startswith("[tool_use:")
        has_real_prompt = bool(prompt.strip()) and not _is_tool_result_only(prompt)

        if has_real_prompt:
            # Start a new exchange
            if current is not None:
                exchanges.append(current)
            current = {
                "start_seq": rec.seq,
                "prompt": prompt,
                "tool_steps": [],
                "final_response": None,
                "artifacts": [],
                "model": rec.turn.model,
                "timestamp": rec.timestamp,
                "records": [rec],
            }
            if is_tool_use:
                current["tool_steps"].append(_parse_tool_names(response))
            else:
                current["final_response"] = response
        elif current is not None:
            # Continuation of current exchange
            current["records"].append(rec)
            if is_tool_use:
                current["tool_steps"].append(_parse_tool_names(response))
            else:
                current["final_response"] = response
            # Collect artifacts
            for a in rec.turn.artifacts:
                current["artifacts"].append(a)
        else:
            # Orphan record before first real prompt
            if is_tool_use:
                continue
            # Standalone response (shouldn't happen much)
            exchanges.append({
                "start_seq": rec.seq,
                "prompt": prompt,
                "tool_steps": [],
                "final_response": response,
                "artifacts": [a for a in rec.turn.artifacts],
                "model": rec.turn.model,
                "timestamp": rec.timestamp,
                "records": [rec],
            })

    if current is not None:
        exchanges.append(current)

    return exchanges


def _is_tool_result_only(prompt: str) -> bool:
    """Check if a prompt is just a tool_result relay (not a real user message)."""
    stripped = prompt.strip()
    return not stripped or stripped.startswith("<") or stripped.startswith("{")


def _parse_tool_names(response: str) -> list[str]:
    """Extract tool names from a response like '[tool_use: Read]\n[tool_use: Bash]'."""
    import re
    return re.findall(r'\[tool_use: (\w+)\]', response)


def _print_exchange(ex, verbose=False):
    """Print a single exchange in a readable chat format."""
    seq_range = f"seq {ex['start_seq']}"
    n_records = len(ex["records"])
    if n_records > 1:
        end_seq = ex["records"][-1].seq
        seq_range = f"seq {ex['start_seq']}–{end_seq}"

    # Header line
    model = ex.get("model") or ""
    model_tag = f" [{model}]" if model else ""
    print(f"{'─' * 72}")
    print(f"  {seq_range}{model_tag}  {ex['timestamp']}")
    print(f"{'─' * 72}")

    # Prompt
    prompt = ex["prompt"]
    if prompt.strip():
        print()
        # Clean up IDE context tags for readability
        clean_prompt = _clean_prompt(prompt)
        print(f"  YOU: {clean_prompt}")

    # Tool steps (collapsed summary)
    if ex["tool_steps"]:
        all_tools = []
        for step in ex["tool_steps"]:
            all_tools.extend(step)
        tool_counts = {}
        for t in all_tools:
            tool_counts[t] = tool_counts.get(t, 0) + 1
        tool_summary = ", ".join(
            f"{name} x{count}" if count > 1 else name
            for name, count in tool_counts.items()
        )
        print(f"\n  TOOLS: {tool_summary}")

    # Artifacts
    if ex["artifacts"]:
        for a in ex["artifacts"]:
            print(f"\n  ARTIFACT: {a.filename} ({a.size_bytes} bytes)")
            if verbose:
                print(f"           sha256={a.sha256}")

    # Final response
    response = ex.get("final_response") or ""
    if response.strip():
        print()
        # Indent response text
        lines = response.split("\n")
        for line in lines:
            print(f"  CLAUDE: {line}" if line == lines[0] else f"          {line}")

    print()


def _clean_prompt(prompt: str) -> str:
    """Strip IDE context tags for cleaner display."""
    import re
    # Remove <ide_opened_file>...</ide_opened_file> tags
    cleaned = re.sub(r'<ide_opened_file>.*?</ide_opened_file>\s*', '', prompt, flags=re.DOTALL)
    # Remove <system-reminder>...</system-reminder> tags
    cleaned = re.sub(r'<system-reminder>.*?</system-reminder>\s*', '', cleaned, flags=re.DOTALL)
    cleaned = cleaned.strip()
    return cleaned if cleaned else "(context-only prompt)"


def cmd_proof(args):
    """Generate a proof bundle from a session."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    deck_dir = get_deck_dir(root)
    sid = resolve_session(args, deck_dir)

    if sid is None:
        print("No sessions found in .claudedeck/")
        sys.exit(1)

    chain_path = deck_dir / f"{sid}.chain.jsonl"
    vault_path = deck_dir / f"{sid}.vault.json"

    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        sys.exit(1)

    chain = Chain.load(chain_path)

    if not vault_path.exists():
        print(f"Vault file not found: {vault_path}")
        print("Cannot generate proof without vault (plaintext needed for disclosure)")
        sys.exit(1)

    with open(vault_path) as f:
        vault_data = json.load(f)

    # Determine which turns to disclose
    if args.seqs:
        seqs = [int(s.strip()) for s in args.seqs.split(",")]
    else:
        seqs = list(range(len(chain.records)))

    from claudedeck.proof import ProofBundle, DisclosedTurn

    disclosed = []
    for seq in seqs:
        entry = vault_data.get(str(seq))
        if entry is None:
            print(f"  warning: seq {seq} not in vault, skipping")
            continue
        disclosed.append(DisclosedTurn(
            seq=seq,
            prompt=entry["prompt"],
            response=entry["response"],
            artifacts=entry.get("artifacts", {}),
        ))

    bundle = ProofBundle(
        chain_records=[rec.to_dict() for rec in chain.records],
        disclosed_turns=disclosed,
    )

    output = Path(args.output) if args.output else deck_dir / f"{sid}.proof.json"
    bundle.save(output)

    print(f"Proof bundle saved: {output}")
    print(f"  disclosed turns: {[d.seq for d in disclosed]}")
    redacted = [r.seq for r in chain.records if r.seq not in seqs]
    if redacted:
        print(f"  redacted turns:  {redacted}")
    print(f"  verify with: python verify_proof.py {output} --verbose")


def cmd_anchor(args):
    """Anchor a session's chain head with the local signing backend."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    deck_dir = get_deck_dir(root)
    sid = resolve_session(args, deck_dir)

    if sid is None:
        print("No sessions found in .claudedeck/")
        sys.exit(1)

    chain_path = deck_dir / f"{sid}.chain.jsonl"
    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        sys.exit(1)

    chain = Chain.load(chain_path)
    if not chain.records:
        print("Chain is empty, nothing to anchor.")
        sys.exit(1)

    from claudedeck.local_anchor import sign_local

    result = sign_local(chain.head_hash, deck_dir)
    if result.success:
        print(f"Chain head anchored locally.")
        print(f"  session:   {sid}")
        print(f"  head:      {format_hash(chain.head_hash, 24)}")
        print(f"  signature: {format_hash(result.signature, 24)}")
        print(f"  key_id:    {format_hash(result.key_id, 24)}")
        print(f"  timestamp: {result.timestamp}")
        print(f"  log_index: {result.log_index}")
    else:
        print(f"Anchor failed: {result.error}")
        sys.exit(1)


def cmd_anchor_verify(args):
    """Verify a local anchor for a session."""
    try:
        root = find_project_root()
    except FileNotFoundError:
        print("Error: not in a project directory")
        sys.exit(1)

    deck_dir = get_deck_dir(root)
    sid = resolve_session(args, deck_dir)

    if sid is None:
        print("No sessions found in .claudedeck/")
        sys.exit(1)

    chain_path = deck_dir / f"{sid}.chain.jsonl"
    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        sys.exit(1)

    chain = Chain.load(chain_path)

    from claudedeck.local_anchor import verify_from_log, _log_path

    log = _log_path(deck_dir)
    if not log.exists():
        print("No anchor log found. Run 'claudedeck anchor' first.")
        sys.exit(1)

    # Find anchors for this chain head in the log
    found = False
    with open(log) as f:
        for line in f:
            entry = json.loads(line.strip())
            if entry["chain_head_hash"] == chain.head_hash:
                found = True
                ok, detail = verify_from_log(
                    chain.head_hash, entry["index"], deck_dir,
                )
                status = "PASS" if ok else "FAIL"
                print(f"  [{status}] log_index={entry['index']}  {detail}")

    if not found:
        print(f"No anchors found for chain head {format_hash(chain.head_hash, 24)}")
        print("Run 'claudedeck anchor' to create one.")
        sys.exit(1)


def cmd_session(args):
    """Run interactive REPL session (legacy mode)."""
    import subprocess
    import readline  # noqa: F811 — enables arrow keys / history in input()
    from datetime import datetime, timezone

    # Import the session REPL code
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    chain_path = output_dir / f"{timestamp}.chain.jsonl"
    vault_path = output_dir / f"{timestamp}.vault.json"

    chain = Chain()

    class SimpleVault:
        def __init__(self, path):
            self.path = path
            self._entries = {}

        def store(self, seq, prompt, response, artifacts=None):
            self._entries[seq] = {"prompt": prompt, "response": response, "artifacts": artifacts or {}}

        def retrieve(self, seq):
            return self._entries.get(seq)

        def save(self):
            with open(self.path, "w") as f:
                json.dump(self._entries, f, indent=2, ensure_ascii=True)

    vault = SimpleVault(vault_path)
    session_id = None
    total_cost = 0.0

    print("claudedeck session — verifiable Claude Code REPL")
    print(f"  chain: {chain_path}")
    print(f"  vault: {vault_path}")
    print(f"  model: {args.model or 'default'}")
    print()

    try:
        while True:
            try:
                prompt = input("you> ").strip()
            except EOFError:
                print()
                break

            if not prompt:
                continue
            if prompt in ("/quit", "/exit", "/q"):
                break

            try:
                cmd = ["claude", "-p", prompt, "--output-format", "json"]
                if session_id:
                    cmd.extend(["-r", session_id])
                if args.model:
                    cmd.extend(["--model", args.model])
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    print(f"  error: {result.stderr.strip()}")
                    continue
                resp = json.loads(result.stdout)
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                print(f"  error: {e}")
                continue

            response_text = resp.get("result", "")
            session_id = resp.get("session_id", session_id)
            cost = resp.get("total_cost_usd", 0)
            total_cost += cost

            record = chain.append_turn(prompt=prompt, response=response_text)
            vault.store(record.seq, prompt=prompt, response=response_text)
            chain.save(chain_path)
            vault.save()

            print()
            print(response_text)
            print(f"  [seq={record.seq} | hash={format_hash(record.record_hash)} | cost=${cost:.4f}]")
            print()

    except KeyboardInterrupt:
        print("\n  interrupted")

    if chain.records:
        chain.save(chain_path)
        vault.save()
        valid, _ = chain.verify()
        print(f"\nSession complete — {len(chain.records)} turns, {'VALID' if valid else 'INVALID'}")
        print(f"  head: {chain.head_hash}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="claudedeck",
        description="claudedeck — cryptographic provenance for Claude Code sessions",
    )
    sub = parser.add_subparsers(dest="command")

    # on
    sub.add_parser("on", help="Enable verification for this project")

    # off
    sub.add_parser("off", help="Disable verification for this project")

    # status
    sub.add_parser("status", help="Show verification status and session info")

    # verify
    p_verify = sub.add_parser("verify", help="Verify chain integrity")
    p_verify.add_argument("session", nargs="?", help="Session ID (default: most recent)")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Inspect chain records in detail")
    p_inspect.add_argument("session", nargs="?", help="Session ID (default: most recent)")

    # show
    p_show = sub.add_parser("show", help="Show full conversation from a session")
    p_show.add_argument("session", nargs="?", help="Session ID (default: most recent)")
    p_show.add_argument("--seq", type=int, help="Show only the exchange starting at this seq")
    p_show.add_argument("--verbose", "-v", action="store_true", help="Show full hashes and details")

    # proof
    p_proof = sub.add_parser("proof", help="Generate a proof bundle")
    p_proof.add_argument("session", nargs="?", help="Session ID (default: most recent)")
    p_proof.add_argument("--seqs", metavar="0,1,2", help="Turns to disclose (default: all)")
    p_proof.add_argument("--output", "-o", help="Output file path")

    # anchor
    p_anchor = sub.add_parser("anchor", help="Anchor chain head with local signing key")
    p_anchor.add_argument("session", nargs="?", help="Session ID (default: most recent)")

    # anchor-verify
    p_anchor_v = sub.add_parser("anchor-verify", help="Verify local anchor for a session")
    p_anchor_v.add_argument("session", nargs="?", help="Session ID (default: most recent)")

    # session (legacy REPL)
    p_session = sub.add_parser("session", help="Interactive REPL session (legacy)")
    p_session.add_argument("--model", "-m", default=None)
    p_session.add_argument("--output-dir", "-o", default="./sessions")

    args = parser.parse_args()

    commands = {
        "on": cmd_on,
        "off": cmd_off,
        "status": cmd_status,
        "verify": cmd_verify,
        "inspect": cmd_inspect,
        "show": cmd_show,
        "proof": cmd_proof,
        "anchor": cmd_anchor,
        "anchor-verify": cmd_anchor_verify,
        "session": cmd_session,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
