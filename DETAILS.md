# Claudedeck Security Model

This document explains every layer of verification in the claudedeck data pipeline — what each layer proves, what it costs an attacker to defeat, and what remains unsolved.

## The Core Claim

Claudedeck aims to let a researcher prove: *"This specific conversation between a human and an AI model produced these specific artifacts, in this specific order, and nothing was added, removed, or modified after the fact."*

## Data Pipeline

### Stage 1: Capture

Claude Code fires a **Stop hook** after every assistant response. The hook reads the session transcript (a JSONL file maintained by Claude Code at `~/.claude/projects/`) and extracts human-assistant turns.

```
Claude Code session transcript (JSONL)
    │
    ▼
┌─────────────────────────────┐
│  hook.py: extract_turns()   │  Identifies real user prompts (promptId field)
│                             │  vs tool_result relays (no promptId).
│  Finds the final assistant  │  Locates the end_turn response for each prompt.
│  response per prompt.       │  Extracts all tool_use blocks in the turn.
└──────────────┬──────────────┘
               │
               ▼
        Turn = (prompt, response, model, request_id, tool_calls, file_operations)
```

**What this proves:** The turn structure accurately reflects what is in Claude Code's local session transcript.

**What this does NOT prove:** That the session transcript itself is authentic — see [The Missing Piece](#the-missing-piece-api-response-signing).

### Stage 2: Hashing

Each turn is hashed independently. Plaintext never enters the chain — only SHA-256 digests.

```
prompt  ──→ SHA-256 ──→ prompt_hash
response ──→ SHA-256 ──→ response_hash
artifacts ──→ SHA-256 per file ──→ [{filename, sha256, size_bytes, attribution}]
```

Hashing uses `canonical_json()` for all structured data: deterministic serialization with sorted keys, no whitespace, `ensure_ascii=True`, and **NFC Unicode normalization** applied recursively to all string values and keys before serialization. This eliminates an entire class of canonicalization attacks (composed vs decomposed Unicode producing different hashes for visually identical content).

The same `canonical_json()` implementation is deliberately duplicated in `verify_proof.py` (the standalone verifier) so that verification never depends on the claudedeck package. An automated test ensures the two implementations stay in sync.

### Stage 3: Chain Construction

Each turn becomes a `ChainRecord` containing:

| Field | Purpose |
|-------|---------|
| `seq` | Monotonic sequence number (0, 1, 2, ...) |
| `nonce` | 256-bit cryptographically random value — prevents brute-force reversal of hashes |
| `turn` | The hashed turn data (prompt_hash, response_hash, artifacts, model, tool_calls) |
| `timestamp` | ISO 8601 UTC timestamp of when the record was created |
| `prev_hash` | SHA-256 of the previous record (or `"GENESIS"` for the first) |
| `chain_id` | Random identifier binding every record to this specific chain instance |
| `record_hash` | SHA-256 of canonical_json(all fields above) — the record's identity |

The `record_hash` is computed over `canonical_json({seq, nonce, turn, timestamp, prev_hash, chain_id})`. The `record_hash` field itself is excluded from its own computation (it's the output, not the input).

**Chain linkage:** Each record's `prev_hash` equals the preceding record's `record_hash`, creating an append-only linked list. Modifying any record changes its `record_hash`, which breaks the `prev_hash` of every subsequent record. An attacker must rewrite the entire chain from the point of modification — and if the chain head has been externally anchored, this is detectable.

**Chain identity:** The `chain_id` is a random nonce generated when a chain is first created. It is included in every record's hash computation. This means:

- Records from chain A cannot be transplanted into chain B (different `chain_id` produces different `record_hash`).
- An attacker cannot create a second chain with cherry-picked records from the original.
- Old chains (created before this feature) still verify correctly — `chain_id` is conditionally included in the hash only when present.

### Stage 4: Persistence

The chain is saved as JSONL (one JSON object per line) with a metadata preamble:

```
{"_meta": true, "chain_id": "a1b2c3...", "version": "0.2.0"}
{"chain_id": "a1b2c3...", "nonce": "...", "prev_hash": "GENESIS", "record_hash": "...", "seq": 0, "timestamp": "...", "turn": {...}}
{"chain_id": "a1b2c3...", "nonce": "...", "prev_hash": "...", "record_hash": "...", "seq": 1, "timestamp": "...", "turn": {...}}
```

**Safety measures on disk writes:**

- **Atomic writes:** All file writes (chain, vault, state, proof bundles) go through `atomic_write()`, which writes to a temporary file in the same directory and then calls `os.replace()` — an atomic operation on POSIX systems. If the process crashes mid-write, the original file is untouched.

- **File locking:** The hook's entire critical section (load chain → process turns → save chain/vault/state) is wrapped in an exclusive advisory file lock (`fcntl.flock`), keyed per session. This prevents concurrent hook invocations from corrupting shared files. Anchor log appends are independently locked.

- **Verify-on-save:** `Chain.save()` calls `Chain.verify()` before writing. If the in-memory chain is corrupted (broken linkage, wrong hashes), the save is refused with a `ChainCorruptedError`. Corrupted data never reaches disk through normal code paths.

- **JSONL resilience:** `Chain.load()` skips malformed lines with a stderr warning instead of crashing. If a file is partially written (despite atomic writes), the valid records are recovered and the gap is reported during verification.

### Stage 5: State Integrity

The hook tracks its progress in a state file (`{session_id}.state.json`) containing `chained_count` (how many turns have been processed) and a filesystem snapshot.

**HMAC protection:** The state file is HMAC-SHA256 signed using the local anchor key (`.claudedeck/local_anchor.key`). On load, the HMAC is verified. If an attacker modifies `chained_count` (e.g., rewinding it to force re-processing of turns), the HMAC mismatch is detected and the state resets.

**Limitation:** An attacker with access to the local anchor key can forge valid HMACs. This protects against casual tampering, not against a fully compromised machine.

### Stage 6: Artifact Attribution

Files produced during a session are attributed to their source using a two-layer system:

**Layer 1 — Tool call extraction (definitive):** The hook parses `tool_use` content blocks from assistant messages. Write and Edit tool calls provide definitive attribution:
- `"claude:Write"` — Claude's Write tool created or overwrote the file
- `"claude:Edit"` — Claude's Edit tool modified the file
- Each artifact records the `source_tool_id` linking it to the specific tool invocation

**Layer 2 — Snapshot diffing (inferred):** Before and after each turn, the hook captures SHA-256 checksums of all tracked files (via `git ls-files`). Files that changed but weren't covered by a Write/Edit tool call get:
- `"claude:Bash(inferred)"` — if a Bash tool was called in the turn (file likely modified by a shell command)
- `"unattributed"` — no matching tool call (likely a user modification between turns)

**Full path tracking:** Artifacts store both `filename` (basename) and `filepath` (relative path from project root). This prevents collisions when different directories contain files with the same name.

### Stage 7: Anchoring

Anchoring binds the chain head hash to an external timestamp service, proving the chain existed in its current state at a specific time.

**The signing airlock:** Before any hash reaches an external service, it passes through `validate_hash_only()` — a strict regex gate (`\A[0-9a-f]{64}\Z`) that structurally ensures only 64-character lowercase hex strings (SHA-256 digests) exit the machine. No plaintext, no metadata, no filenames can leak through this boundary. The regex uses `\A...\Z` anchors (not `^...$`) to prevent Python's multiline matching from allowing trailing newlines.

**Anchor backends:**

| Backend | What it proves | Trust model |
|---------|---------------|-------------|
| **Local HMAC** | Signer held `.claudedeck/local_anchor.key` at signing time | Self-attested (dev/testing only) |
| **Sigstore** | An OIDC-authenticated identity signed hash H at time T, recorded in the public Rekor transparency log | Trust in Sigstore infrastructure + OIDC provider |
| **OpenTimestamps** | Hash H was committed to the Bitcoin blockchain at time T | Trust in Bitcoin consensus (trustless after confirmation) |

**Anchor log integrity:** Each anchor log entry is HMAC-signed using the local anchor key. On read, the HMAC is verified and an `_hmac_valid` flag is set. Tampered entries are flagged. Old entries (created before HMAC was added) are treated as legacy, not as failures.

### Stage 8: Proof Bundles

A proof bundle is a self-contained, portable verification package:

```json
{
  "version": "0.2.0",
  "chain_records": [ ... all records (hashes only) ... ],
  "disclosed_turns": [ ... selected turns with plaintext ... ],
  "anchors": [ ... external anchor references ... ],
  "metadata": { "researcher": "...", "purpose": "..." }
}
```

**Selective disclosure:** The researcher chooses which turns to reveal. The full chain (hashes only) is always included so verifiers can check linkage. Undisclosed turns remain private — a verifier can confirm they exist and are linked, but cannot read their content.

**What verification checks:**

1. **Chain integrity** — Every `record_hash` matches `SHA-256(canonical_json(hashable_fields))`. Every `prev_hash` matches the preceding record's `record_hash`. Seq numbers are monotonic.
2. **Disclosed content** — `SHA-256(prompt)` matches `prompt_hash` in the corresponding chain record. Same for responses.
3. **Artifact hashes** — Disclosed artifact content hashes match the chain record's artifact SHA-256 values.
4. **Anchor references** — Anchor `chain_head_hash` matches the actual chain head. (Full external verification requires Sigstore/OTS CLI tools.)

**Standalone verification:** `verify_proof.py` is a single-file verifier with zero external dependencies (Python stdlib only). It deliberately duplicates `sha256_hex()` and `canonical_json()` from `core.py` so that anyone can verify a proof bundle without installing claudedeck or trusting its code. An automated test ensures the duplicated implementations stay in sync.

## What Each Layer Proves

Working from the inside out:

| Layer | Guarantee | Cost to defeat |
|-------|-----------|----------------|
| **Record hashing** | Content has not changed since the record was created | Must rewrite the record AND all subsequent records |
| **Chain linkage** | No records have been inserted, removed, or reordered | Must rewrite the entire chain from the point of modification |
| **Chain identity** | Records belong to this chain, not transplanted from another | Must forge a chain with the same `chain_id` |
| **Nonce** | Prompt/response hashes cannot be brute-forced from the chain | Must break SHA-256 preimage resistance (computationally infeasible) |
| **Atomic writes** | On-disk data is never in a partially-written state | Must corrupt the filesystem at the kernel level |
| **File locking** | Concurrent hook invocations cannot corrupt shared files | Must bypass POSIX advisory locks |
| **Verify-on-save** | Corrupted chains cannot be written through normal code paths | Must write directly to the file, bypassing Chain.save() |
| **State HMAC** | Hook progress state has not been tampered with | Must possess the local anchor key |
| **Anchor log HMAC** | Anchor entries have not been modified after creation | Must possess the local anchor key |
| **Unicode normalization** | Visually identical strings always hash identically | N/A — eliminates the attack vector entirely |
| **Artifact filepath** | File attribution is unambiguous across directories | N/A — eliminates filename collision |
| **Signing airlock** | No plaintext can accidentally reach external services | Must modify the source code |
| **Local anchor** | Signer held the key at signing time | Must possess the key file |
| **Sigstore anchor** | Hash existed at time T, signed by OIDC identity | Must compromise Sigstore + OIDC provider |
| **OTS anchor** | Hash was committed to Bitcoin at time T | Must compromise Bitcoin consensus (infeasible) |

## What Selective Disclosure Means for Verifiers

A proof bundle may disclose only a subset of turns. A verifier should understand:

- The full chain (hashes) is present — you can verify that N total turns occurred and that they are linked.
- You can see exactly which turns are disclosed and which are redacted.
- Redacted turns could contain anything — the researcher chose not to reveal them.
- If turns 0 and 2 are disclosed but turn 1 is not, the conversation context between them is hidden. This is by design (privacy), but verifiers should note what fraction of the chain is disclosed.

## The Missing Piece: API Response Signing

Everything described above proves that the chain is internally consistent, that it hasn't been modified since anchoring, and that the content hashes match the disclosed plaintext. **What it does not prove is that Claude actually generated the responses.**

### The gap

The session transcript that claudedeck reads is a local JSONL file maintained by Claude Code. A sufficiently motivated attacker could:

1. Hand-craft a fake session JSONL with fabricated assistant responses.
2. Run the claudedeck hook on this fake transcript.
3. Produce a cryptographically valid chain, anchor it, and create a proof bundle.
4. The proof bundle would pass every verification check — chain integrity, hash matching, anchor validation — because the chain was legitimately constructed from the (fake) input.

This is not a bug in claudedeck. It is a fundamental limitation: **claudedeck can verify the integrity of a conversation log, but cannot verify its authenticity without cooperation from the API provider.**

### What would fix it

If Anthropic's API added **response signing** — a cryptographic signature over each response, bound to the request ID and model version — claudedeck could verify that each response in the chain was genuinely produced by Claude's servers. The infrastructure is ready:

- `api_request_id` is already captured in every chain record's `TurnData`.
- The chain's `model` field records which model produced each response.
- The signing airlock and anchor system are already designed to handle cryptographic attestations.

The signature could be as simple as:

```
X-Anthropic-Signature: ECDSA(server_private_key, SHA-256(request_id || response_body))
```

With this single addition from Anthropic, claudedeck's verification stack would close completely: from "Claude generated this response" (API signature) through "this response was part of this conversation" (chain integrity) to "this conversation existed at this time" (external anchor).

### Current mitigations

Without API response signing, claudedeck still provides meaningful evidence:

- **API request IDs** are recorded. If Anthropic ever provides a request verification endpoint, these IDs could be checked retroactively.
- **Model field** records the claimed model version. While not authenticated, it provides a correlation point.
- **Timestamp plausibility** — the chain timestamps and anchor timestamps can be cross-referenced. A forger would need to create the fake session AND anchor it within a plausible time window.
- **Behavioral analysis** — Claude's responses have stylistic signatures (tool use patterns, reasoning structure) that are difficult to fabricate convincingly at scale.

None of these are cryptographic proof. They are circumstantial evidence. The gap between "circumstantial" and "cryptographic" is exactly the gap that API response signing would close.

## Threat Model Summary

| Attacker capability | Blocked by | Still possible? |
|---------------------|-----------|----------------|
| Modify a response after recording | Chain hash linkage | No |
| Insert a fake turn | Chain linkage + seq monotonicity | No |
| Remove a turn | Chain linkage (gap detected) | No |
| Reorder turns | Chain linkage + prev_hash | No |
| Transplant records between chains | chain_id binding | No |
| Tamper with hook state (rewind progress) | State file HMAC | No (without key) |
| Edit anchor log entries | Anchor log HMAC | No (without key) |
| Corrupt chain via concurrent writes | File locking + atomic writes | No |
| Save a corrupted chain | Verify-on-save | No (through normal API) |
| Exploit Unicode normalization differences | NFC normalization in canonical_json | No |
| Leak plaintext to signing services | Signing airlock regex | No |
| Backdate a chain | External anchoring (Sigstore/OTS) | No (if anchored) |
| **Fabricate a Claude response from scratch** | **Nothing (requires API response signing)** | **Yes** |

The last row is the only remaining gap. Every other attack vector is addressed by the current system.

## Test Coverage

The security properties described in this document are backed by 532 automated tests, including:

- **180 security-focused tests** covering spoofing attacks, chain manipulation, JSONL format attacks, canonical JSON edge cases, signing airlock boundary conditions, anchor trust model attacks, and malformed input handling.
- **Tests documenting the remaining gap** — `test_spoofing.py` includes tests that demonstrate forged sessions and proof bundles currently pass verification, clearly marking the boundary of what claudedeck can and cannot prove without API response signing.

```bash
python -m pytest tests/ -v    # 532 tests, all passing
```
