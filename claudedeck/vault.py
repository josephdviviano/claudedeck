"""
claudedeck.vault — Encrypted storage for session plaintext.

The chain file (JSONL) contains only hashes and is safe to publish.
The vault contains the actual prompts/responses, encrypted at rest.
Researchers selectively disclose entries when they want to prove provenance.

Requires: pip install cryptography
"""

import base64
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # OWASP 2023 recommendation
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


class Vault:
    """Encrypted key-value store for session plaintext.

    Each entry is keyed by chain sequence number and contains the
    raw prompt, response, and optionally the artifact contents.
    """

    def __init__(self, path: str | Path, passphrase: str):
        self.path = Path(path)
        self._entries: dict[int, dict] = {}

        if self.path.exists():
            self._load(passphrase)
        else:
            self._salt = os.urandom(16)
            self._key = _derive_key(passphrase, self._salt)

    def _load(self, passphrase: str):
        raw = self.path.read_bytes()
        # First 16 bytes are the salt
        self._salt = raw[:16]
        self._key = _derive_key(passphrase, self._salt)
        f = Fernet(self._key)
        plaintext = f.decrypt(raw[16:])
        self._entries = json.loads(plaintext)
        # JSON keys are strings; convert back to int
        self._entries = {int(k): v for k, v in self._entries.items()}

    def save(self):
        """Encrypt and write vault to disk."""
        f = Fernet(self._key)
        plaintext = json.dumps(
            {str(k): v for k, v in self._entries.items()},
            ensure_ascii=True,
        ).encode("utf-8")
        encrypted = f.encrypt(plaintext)
        self.path.write_bytes(self._salt + encrypted)

    def store(self, seq: int, prompt: str, response: str, artifacts: dict[str, str] | None = None):
        """Store a turn's plaintext content.

        Args:
            seq: Chain sequence number (links vault entry to chain record).
            prompt: Raw prompt text.
            response: Raw response text.
            artifacts: Optional dict of {filename: content_string} for text artifacts.
                       Binary artifacts should be base64-encoded.
        """
        self._entries[seq] = {
            "prompt": prompt,
            "response": response,
            "artifacts": artifacts or {},
        }

    def retrieve(self, seq: int) -> Optional[dict]:
        """Retrieve a single entry by sequence number."""
        return self._entries.get(seq)

    def list_entries(self) -> list[int]:
        """List all stored sequence numbers."""
        return sorted(self._entries.keys())
