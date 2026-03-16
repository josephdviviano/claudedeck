"""
claudedeck.integrity — HMAC-based integrity checking for local files.

Provides tamper detection for state files and anchor log entries
using the local_anchor.key as the HMAC key. This does NOT prevent
an attacker who has the key from forging HMACs — it detects
modifications by actors without key access.
"""

import hashlib
import hmac
from pathlib import Path

from .core import canonical_json


def _load_key(deck_dir: Path) -> bytes:
    """Load the local anchor key (must already exist)."""
    from .local_anchor import _load_or_create_key
    key, _ = _load_or_create_key(deck_dir)
    return key


def compute_hmac(data: bytes, deck_dir: Path) -> str:
    """Compute HMAC-SHA256 of data using the local anchor key."""
    key = _load_key(deck_dir)
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, expected_hmac: str, deck_dir: Path) -> bool:
    """Verify HMAC-SHA256 of data. Returns False on mismatch or error."""
    try:
        key = _load_key(deck_dir)
        actual = hmac.new(key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(actual, expected_hmac)
    except (OSError, ValueError):
        return False


def hmac_json(obj: dict, deck_dir: Path) -> str:
    """Compute HMAC-SHA256 of a dict via canonical_json serialization."""
    return compute_hmac(canonical_json(obj), deck_dir)


def verify_hmac_json(obj: dict, expected_hmac: str, deck_dir: Path) -> bool:
    """Verify HMAC-SHA256 of a dict via canonical_json serialization."""
    return verify_hmac(canonical_json(obj), expected_hmac, deck_dir)
