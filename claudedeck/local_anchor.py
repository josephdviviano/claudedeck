"""
claudedeck.local_anchor — Local signing backend for testing and development.

Provides a self-contained anchor service that signs chain heads using
HMAC-SHA256 with a local key file. This lets you test the full
record → chain → anchor → proof → verify flow without external services.

NOT a substitute for Sigstore/OTS in production. The local anchor proves
that the signer held a specific key at signing time, but there's no
independent third party attesting to the timestamp.

Key file: .claudedeck/local_anchor.key (auto-generated on first use)
Anchor log: .claudedeck/anchor_log.jsonl (append-only record of all anchors)
"""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .signing import validate_hash_only


ANCHOR_TYPE = "local"


@dataclass
class LocalAnchorResult:
    success: bool
    signature: Optional[str] = None
    key_id: Optional[str] = None
    timestamp: Optional[str] = None
    log_index: Optional[int] = None
    error: Optional[str] = None


def _key_path(deck_dir: Path) -> Path:
    return deck_dir / "local_anchor.key"


def _fingerprint_path(deck_dir: Path) -> Path:
    return deck_dir / "key_fingerprint"


def _log_path(deck_dir: Path) -> Path:
    return deck_dir / "anchor_log.jsonl"


def _load_or_create_key(deck_dir: Path) -> tuple[bytes, str]:
    """Load the local signing key, or generate one if it doesn't exist.

    Returns (key_bytes, key_id) where key_id is the SHA-256 of the key
    (safe to embed in proof bundles — it identifies the key without
    revealing it).

    On first key creation, writes a fingerprint file so that key
    replacement can be detected. On subsequent loads, warns to stderr
    if the key_id doesn't match the pinned fingerprint.
    """
    import sys

    kp = _key_path(deck_dir)
    fp = _fingerprint_path(deck_dir)
    if kp.exists():
        key = kp.read_bytes()
    else:
        deck_dir.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        kp.write_bytes(key)
        kp.chmod(0o600)  # owner-only read/write

    key_id = hashlib.sha256(key).hexdigest()

    # Pin or verify fingerprint
    if fp.exists():
        pinned = fp.read_text().strip()
        if pinned != key_id:
            print(
                f"WARNING: Local anchor key fingerprint mismatch!\n"
                f"  Pinned:  {pinned[:16]}...\n"
                f"  Current: {key_id[:16]}...\n"
                f"  The key may have been regenerated. Old anchors signed with "
                f"the previous key cannot be verified with the current key.",
                file=sys.stderr,
            )
    else:
        # First time — pin the fingerprint
        deck_dir.mkdir(parents=True, exist_ok=True)
        fp.write_text(key_id + "\n")

    return key, key_id


def check_key_consistency(deck_dir: Path) -> tuple[bool, str]:
    """Check if the current key matches all key_ids in the anchor log.

    Returns (is_consistent, detail_message).
    """
    kp = _key_path(deck_dir)
    if not kp.exists():
        return True, "No local anchor key present"

    key = kp.read_bytes()
    current_id = hashlib.sha256(key).hexdigest()

    log = _log_path(deck_dir)
    if not log.exists():
        return True, "No anchor log entries to check"

    mismatched = []
    with open(log) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            entry_key_id = entry.get("key_id")
            if entry_key_id and entry_key_id != current_id:
                mismatched.append(entry.get("index", "?"))

    if mismatched:
        return False, (
            f"Key rotation detected: log entries {mismatched} were signed with a different key "
            f"(current key_id: {current_id[:16]}...)"
        )
    return True, f"All log entries consistent with current key (key_id: {current_id[:16]}...)"


def export_key_fingerprint(deck_dir: Path) -> str:
    """Return the current key's SHA-256 fingerprint for out-of-band recording."""
    kp = _key_path(deck_dir)
    if not kp.exists():
        raise FileNotFoundError("No local anchor key found")
    key = kp.read_bytes()
    return hashlib.sha256(key).hexdigest()


def sign_local(chain_head_hash: str, deck_dir: Path) -> LocalAnchorResult:
    """Sign a chain head hash with the local HMAC key.

    The signature covers: chain_head_hash + timestamp, so a verifier
    can confirm both the hash and the claimed signing time are authentic.
    """
    safe_hash = validate_hash_only(chain_head_hash)
    key, key_id = _load_or_create_key(deck_dir)

    timestamp = datetime.now(timezone.utc).isoformat()

    # Sign: HMAC-SHA256(key, hash || timestamp)
    message = f"{safe_hash}:{timestamp}".encode("utf-8")
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()

    # Append to anchor log (with file lock and HMAC)
    from .core import file_lock
    log = _log_path(deck_dir)
    with file_lock(log):
        log_index = _count_lines(log)
        entry = {
            "index": log_index,
            "chain_head_hash": safe_hash,
            "timestamp": timestamp,
            "signature": signature,
            "key_id": key_id,
        }
        try:
            from .integrity import hmac_json
            entry["_hmac"] = hmac_json(entry, deck_dir)
        except Exception:
            pass
        with open(log, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    return LocalAnchorResult(
        success=True,
        signature=signature,
        key_id=key_id,
        timestamp=timestamp,
        log_index=log_index,
    )


def verify_local(
    chain_head_hash: str,
    signature: str,
    timestamp: str,
    deck_dir: Path,
) -> tuple[bool, str]:
    """Verify a local anchor signature.

    Returns (is_valid, detail_message).
    """
    safe_hash = validate_hash_only(chain_head_hash)

    kp = _key_path(deck_dir)
    if not kp.exists():
        return False, "Local anchor key not found"

    key = kp.read_bytes()
    message = f"{safe_hash}:{timestamp}".encode("utf-8")
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()

    if hmac.compare_digest(signature, expected):
        return True, f"Local anchor signature valid (signed at {timestamp})"
    else:
        return False, "Local anchor signature INVALID — hash or timestamp was modified"


def verify_from_log(
    chain_head_hash: str,
    log_index: int,
    deck_dir: Path,
) -> tuple[bool, str]:
    """Verify a local anchor by looking it up in the anchor log."""
    log = _log_path(deck_dir)
    if not log.exists():
        return False, "Anchor log not found"

    with open(log) as f:
        for i, line in enumerate(f):
            if i == log_index:
                entry = json.loads(line.strip())
                if entry["chain_head_hash"] != chain_head_hash:
                    return False, f"Log entry {log_index}: chain_head_hash mismatch"
                return verify_local(
                    entry["chain_head_hash"],
                    entry["signature"],
                    entry["timestamp"],
                    deck_dir,
                )

    return False, f"Log entry {log_index} not found (log has fewer entries)"


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path) as f:
        return sum(1 for _ in f)
