# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The purpose of this project is to wrap claude code to make the entire conversation fully verifiable using cryptographic hashing.

The session JSONL files in ~/.claude/projects/ have structured turn data with roles, content blocks, and tool use — you'll want to flatten each assistant turn's content blocks into a single string before hashing, and decide whether tool use/tool results count as separate chain records or get folded into the parent turn. I'd lean toward treating each human→assistant exchange as one record, with tool calls embedded in the response hash.

The api_request_id field is the one thing you can't get from the local JSONL — it comes from the HTTP response headers. If you end up wrapping the CLI at the pty level you won't have it. But if you later hook into the API directly (or Anthropic exposes it in the session logs), it slots right into the existing TurnData model.

If we structure your proof bundles to emit C2PA-compatible manifests, your verification story would plug into an ecosystem that Google, Adobe, Microsoft, and OpenAI are already investing in. That's a much bigger interoperability win than integrating with a startup's signing API. And if Anthropic eventually adds response signing, they'd almost certainly use C2PA rather than a proprietary format.

## Project Overview

**claudedeck** — Cryptographic provenance for AI coding sessions. Creates hash chains over prompt/response turns, binds artifacts to specific moments, and anchors chains to external timestamp services (local HMAC, Sigstore, OpenTimestamps) for independent verifiability.

## Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Enable verification for a project (installs Claude Code Stop hook)
claudedeck on

# Check status, verify chains, inspect records, show conversations
claudedeck status
claudedeck verify [SESSION_ID]
claudedeck inspect [SESSION_ID]
claudedeck show [SESSION_ID]

# Anchor chain head (local, sigstore, ots, or all)
claudedeck anchor [SESSION_ID] [--backend local|sigstore|ots|all]
claudedeck anchor-verify [SESSION_ID] [--backend local|sigstore|ots]

# Generate a proof bundle (selective disclosure)
claudedeck proof [SESSION_ID] [--seqs 0,1,3] [--no-anchors]

# Disable verification
claudedeck off

# Run end-to-end demo
python demo.py

# Verify a proof bundle (zero dependencies)
python verify_proof.py <bundle.json> [--verbose] [--check-artifact <file>]

# Run test suite (185 tests)
python -m pytest tests/ -v
```

## Architecture

The `claudedeck/` package contains:

- **`__main__.py`** — CLI with subcommands: `on`, `off`, `status`, `verify`, `inspect`, `show`, `proof`, `anchor`, `anchor-verify`, `session`.
- **`hook.py`** — Claude Code `Stop` hook. Reads session JSONL transcripts, extracts turns, appends to hash chain. Runs silently after each assistant response.
- **`settings.py`** — Project settings management. Installs/removes the hook in `.claude/settings.local.json`.
- **`core.py`** — Hash chain data model (`Chain`, `ChainRecord`, `TurnData`, `ArtifactRef`). Append-only chain with JSONL persistence. Zero external dependencies (stdlib only). All hashing uses `canonical_json()` for deterministic serialization.
- **`vault.py`** — Encrypted storage for session plaintext (Fernet + PBKDF2). Requires `cryptography` package. Entries keyed by chain sequence number.
- **`proof.py`** — Proof bundle creation and verification (`ProofBundle`, `create_proof_bundle`, `verify_proof_bundle`). Supports selective disclosure — researcher chooses which turns to reveal. `AnchorRef` supports embedded proof data (base64) for portable OTS proofs.
- **`signing.py`** — "Signing airlock" that structurally ensures only 64-char SHA-256 hex digests reach external services. Contains `sign_with_sigstore`, `stamp_with_ots`, `verify_with_sigstore`, `verify_with_ots`, and `anchor_chain_head`. Security-critical module.
- **`anchoring.py`** — Unified anchor orchestrator. Dispatches to local, Sigstore, or OpenTimestamps backends via `anchor()` and `anchor_all()`. Writes all results to a single `anchor_log.jsonl` with a uniform schema. Handles verification dispatch via `verify_anchor()`.
- **`local_anchor.py`** — Local signing backend for dev/testing. HMAC-SHA256 with an auto-generated key (`.claudedeck/local_anchor.key`, mode 0o600). Append-only anchor log. Not a substitute for Sigstore/OTS in production.
- **`verify_proof.py`** — Standalone verifier script (root level). Intentionally duplicates core hash logic so it has zero dependencies and can be distributed independently. Prints backend-specific verification instructions.
- **`demo.py`** — Simulates a full session: record turns, encrypt vault, create proof bundle, verify, and demonstrate tamper detection.

### Key design constraints

- **Verification path must be stdlib-only** — `core.py`, `proof.py`, and `verify_proof.py` must never depend on third-party packages so anyone can verify without trusting external code.
- **The signing airlock** (`signing.py:validate_hash_only`) is the single point where data exits the machine. Only fixed-length hex hashes pass through — never plaintext or metadata. Uses `\A[0-9a-f]{64}\Z` regex (not `^...$` which allows trailing newline in Python).
- **`canonical_json()`** (sorted keys, no whitespace, `ensure_ascii=True`) is the canonical serialization for all hashing. Any change to this function breaks all existing chains.
- **`verify_proof.py` deliberately duplicates** `sha256_hex` and `canonical_json` from `core.py` to remain standalone.
- **Graceful degradation** — missing `cosign` or `ots` CLIs produce informative errors, never crashes. Local anchoring always works.
- **Backward compatibility** — old anchor log entries without `anchor_type` are treated as `"local"`.

### Data flow

Chain file (`.chain.jsonl`) contains only hashes — safe to publish. Vault (`.vault.json`) contains plaintext — stays private. Proof bundles contain the full chain plus selectively disclosed plaintext for chosen turns. Anchors from the anchor log are auto-included in proof bundles.

### Development Env
use my `claudedeck` conda environment during development.
