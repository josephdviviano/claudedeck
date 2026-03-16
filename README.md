# claudedeck

Cryptographic provenance for AI coding sessions. Prove that a specific interaction with an AI model produced a specific result — with no omissions, no insertions, and no modifications.

Named after the Ono-Sendai cyberspace deck from Neuromancer — the trust interface between human and digital space.

## Quick Start

### Install

```bash
pip install -e .                   # core (stdlib only)
pip install -e ".[vault]"          # + encrypted vault (requires cryptography)
pip install -e ".[dev]"            # + test dependencies
```

### Enable verification

```bash
cd your-project/
claudedeck on                      # installs a Claude Code Stop hook
```

That's it. Run `claude` normally — every prompt/response turn is automatically hashed and chained in the background. You keep the full CLI experience (streaming, tool use, everything).

### Inspect what's been recorded

```bash
claudedeck status                  # overview of all sessions
claudedeck show                    # read the conversation back
claudedeck show --seq 22           # jump to a specific exchange
claudedeck inspect                 # detailed chain record view
```

### Verify chain integrity

```bash
claudedeck verify                  # verify the hash chain
```

### Anchor the chain head

Anchoring binds the chain head hash to an external timestamp service, proving the chain existed at a specific time.

```bash
# Local anchor (always works, no external tools needed)
claudedeck anchor

# Sigstore — signs via OIDC, records in Rekor transparency log
# Requires: https://docs.sigstore.dev/cosign/installation/
claudedeck anchor --backend sigstore

# OpenTimestamps — Bitcoin-attested timestamps
# Requires: pip install opentimestamps-client
claudedeck anchor --backend ots

# All backends at once (local always succeeds; others fail gracefully)
claudedeck anchor --backend all
```

### Verify anchors

```bash
claudedeck anchor-verify           # verify all anchors for the session
claudedeck anchor-verify -b sigstore  # verify only sigstore anchors
```

### Generate a proof bundle

Proof bundles are self-contained packages for auditors. They include the full chain (hashes only) plus selectively disclosed plaintext for chosen turns.

```bash
claudedeck proof                   # disclose all turns
claudedeck proof --seqs 0,2,5      # selective disclosure
claudedeck proof --no-anchors      # exclude anchor references
```

Anchors from the anchor log are auto-included in proof bundles.

### Verify a proof bundle (zero dependencies)

Anyone can verify a proof bundle with just Python — no need to install claudedeck:

```bash
python verify_proof.py bundle.proof.json --verbose
python verify_proof.py bundle.proof.json --check-artifact script.py
```

### Disable verification

```bash
claudedeck off                     # removes the hook; chain data is preserved
```

## The Problem

A researcher uses Claude Code to develop an analysis pipeline. They publish the results. A reviewer asks: "How do I know you didn't cherry-pick prompts, edit responses, or add steps after the fact?"

## How It Works

claudedeck runs as a **Claude Code Stop hook** — it fires silently after each assistant response, reading the session transcript and appending to an append-only hash chain. No wrapper, no proxy, no modified CLI.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                  RESEARCHER'S MACHINE                │
│                                                      │
│  Claude Code ──→ Chain Builder ──→ session.chain.jsonl│
│       │              │                (hashes only)  │
│       │              ▼                               │
│       │         Vault (plaintext)                     │
│       │         session.vault.json                    │
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
          ┌─────────┼─────────┐
          ▼         ▼         ▼
   ┌──────────┐ ┌────────┐ ┌──────────────┐
   │  Local   │ │Sigstore│ │ OpenTimestamps│
   │  HMAC    │ │(Rekor) │ │  (Bitcoin)    │
   │          │ │        │ │              │
   │ Dev/test │ │Identity│ │ Permanent    │
   │ + fast   │ │+ audit │ │ + trustless  │
   └──────────┘ └────────┘ └──────────────┘
```

### What goes where

| Data | Where it lives | Who sees it |
|------|---------------|-------------|
| Prompts & responses (plaintext) | Vault file (local) | Only the researcher |
| Hashes of prompts/responses | Chain file (publishable) | Anyone |
| Artifact file hashes | Chain file (publishable) | Anyone |
| Random nonce per record | Chain file | Anyone (prevents brute-force) |
| Chain head hash | Anchor services | Anyone |
| OIDC identity (if Sigstore) | Sigstore Rekor log | Anyone |

### Security properties

| Threat | Mitigation |
|--------|-----------|
| Tamper with a response | Chain hash breaks — detected by any verifier |
| Insert/remove a turn | Chain linkage breaks — detected by any verifier |
| Forge timestamps | Would require compromising Sigstore AND/OR Bitcoin |
| Brute-force prompt from hash | Random nonce makes this computationally infeasible |
| Accidental content leakage to signing services | Signing airlock structurally accepts only 64-char hex |

### What this does NOT prove (yet)

- **That Claude actually generated the responses.** This would require Anthropic to co-sign responses server-side. The chain logs API request IDs as correlation evidence, but these aren't cryptographic attestations.

## CLI Reference

| Command | Description |
|---------|-------------|
| `claudedeck on` | Enable verification (installs Stop hook) |
| `claudedeck off` | Disable verification (preserves chain data) |
| `claudedeck status` | Show verification status and session info |
| `claudedeck verify [SESSION]` | Verify chain integrity |
| `claudedeck inspect [SESSION]` | Inspect chain records in detail |
| `claudedeck show [SESSION]` | Show full conversation in readable format |
| `claudedeck proof [SESSION]` | Generate a proof bundle |
| `claudedeck anchor [SESSION]` | Anchor chain head to external service |
| `claudedeck anchor-verify [SESSION]` | Verify anchor signatures |

### Anchor backends

| Backend | Flag | Requires | What it proves |
|---------|------|----------|---------------|
| Local HMAC | `--backend local` (default) | Nothing | Signer held key at signing time |
| Sigstore | `--backend sigstore` | `cosign` CLI | Identity + timestamp in public log |
| OpenTimestamps | `--backend ots` | `ots` CLI | Bitcoin-attested timestamp |
| All | `--backend all` | Optional | Best available attestation |

## Roadmap

- [ ] C2PA-compatible manifest output (interop with Adobe/Google/Microsoft content provenance ecosystem)
- [ ] Merkle tree for efficient partial verification of long sessions
- [ ] Integration with Anthropic's API response headers (api_request_id correlation)
- [ ] Server-side response co-signing (pending Anthropic support)
- [ ] Encrypted vault with passphrase-based key derivation

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests (185 tests)
pytest

# Run the legacy demo
python demo.py
```

## License

MIT
