# claudedeck

Cryptographic provenance for AI coding sessions. Prove that a specific interaction with an AI model produced a specific result — with no omissions, no insertions, and no modifications.

## The Problem

A researcher uses Claude Code to develop an analysis pipeline. They publish the results. A reviewer asks: "How do I know you didn't cherry-pick prompts, edit responses, or add steps after the fact?"

## The Solution

`claudedeck` creates a **hash chain** over each prompt/response turn, binding artifacts (scripts, files, outputs) to specific moments in the conversation. The chain is anchored to external timestamp services (Sigstore + OpenTimestamps) for independent verifiability.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                  RESEARCHER'S MACHINE                │
│                                                      │
│  Claude Code ──→ Chain Builder ──→ session.chain.jsonl│
│       │              │                (hashes only)  │
│       │              ▼                               │
│       │         Vault (encrypted)                    │
│       │         session.vault                        │
│       │              │                               │
│       ▼              ▼                               │
│   Artifacts    Proof Bundle                          │
│   (scripts,    (selective disclosure)                │
│    outputs)         │                                │
│                     ▼                                │
│  ┌──────────── SIGNING AIRLOCK ───────────┐         │
│  │  Only 64-char SHA-256 hex passes here  │         │
│  └────────────────┬───────────────────────┘         │
└───────────────────┼─────────────────────────────────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   ┌─────────────┐    ┌──────────────┐
   │  Sigstore   │    │ OpenTimestamps│
   │  (Rekor)    │    │  (Bitcoin)    │
   │             │    │              │
   │ Immediate   │    │ Permanent    │
   │ + Identity  │    │ + Trustless  │
   └─────────────┘    └──────────────┘
```

### What goes where

| Data | Where it lives | Who sees it |
|------|---------------|-------------|
| Prompts & responses (plaintext) | Encrypted vault (local) | Only the researcher |
| Hashes of prompts/responses | Chain file (publishable) | Anyone |
| Artifact file hashes | Chain file (publishable) | Anyone |
| Random nonce per record | Chain file | Anyone (prevents brute-force) |
| Chain head hash | Sigstore + OTS | Anyone |
| OIDC identity (if keyless signing) | Sigstore Rekor log | Anyone |

### Security properties

| Threat | Mitigation |
|--------|-----------|
| Tamper with a response | Chain hash breaks — detected by any verifier |
| Insert/remove a turn | Chain linkage breaks — detected by any verifier |
| Forge timestamps | Would require compromising both Sigstore AND Bitcoin |
| Brute-force prompt from hash | Random nonce makes this computationally infeasible |
| Accidental content leakage to signing services | Signing airlock structurally accepts only 64-char hex |
| Vault compromised on disk | AES encryption via passphrase (PBKDF2, 600k iterations) |

### What this does NOT prove (yet)

- **That Claude actually generated the responses.** This would require Anthropic to co-sign responses server-side. The chain logs API request IDs as correlation evidence, but these aren't cryptographic attestations.

## Quick Start

```bash
pip install cryptography

# Run the demo
python demo.py

# Verify a proof bundle (zero dependencies)
python verify_proof.py proof_bundle.json --verbose
```

## Usage

### Recording a session

```python
from claudedeck import Chain
from claudedeck.vault import Vault

chain = Chain()
vault = Vault("session.vault", passphrase="your-passphrase")

# After each Claude Code turn:
record = chain.append_turn(
    prompt="Write a function to compute GC content",
    response="Here's a function that computes GC content from a DNA sequence...",
    artifact_paths=["gc_content.py"],
    model="claude-sonnet-4-20250514",
    api_request_id="req_01ABC123",  # from API response headers
)

vault.store(record.seq, prompt=..., response=..., artifacts={"gc_content.py": ...})
vault.save()
chain.save("session.chain.jsonl")
```

### Creating a proof bundle

```python
from claudedeck.proof import create_proof_bundle, AnchorRef

bundle = create_proof_bundle(
    chain=chain,
    vault=vault,
    disclose_seqs=[0, 2, 5],  # choose which turns to reveal
    metadata={
        "researcher": "Your Name",
        "orcid": "0000-0002-XXXX-XXXX",
        "purpose": "Supplementary material for [paper title]",
    },
)
bundle.save("proof_bundle.json")
```

### Anchoring to external services

```python
from claudedeck.signing import anchor_chain_head

results = anchor_chain_head(chain.head_hash)
# results["sigstore"].rekor_log_index → "12345678"
# results["ots"].proof_path → "session_head.sha256.ots"
```

### Verifying (as an auditor)

```bash
# Zero dependencies — just Python stdlib
python verify_proof.py proof_bundle.json --verbose

# Check a specific artifact file
python verify_proof.py proof_bundle.json --check-artifact gc_content.py
```

## Roadmap

- [ ] Real-time Claude Code wrapper (pty-based session capture)
- [ ] `claudedeck record` CLI command
- [ ] `claudedeck seal` — finalize + anchor a session
- [ ] `claudedeck prove` — interactive proof bundle builder
- [ ] Merkle tree for efficient partial verification of long sessions
- [ ] Integration with Anthropic's API response headers
- [ ] Server-side co-signing (pending Anthropic support)

## License

MIT
