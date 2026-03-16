"""
claudedeck.core — Hash chain data model and operations.

Zero external dependencies (stdlib only) so that verification
never requires trusting third-party code.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Hashing primitives
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256, return lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Stream-hash a file without loading it entirely into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing.

    Rules: sorted keys, no whitespace, ensure_ascii=True.
    Any two implementations following these rules will produce
    identical bytes for the same logical object.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def generate_nonce(nbytes: int = 32) -> str:
    """Generate a cryptographically random nonce (hex-encoded)."""
    return secrets.token_hex(nbytes)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ArtifactRef:
    """A content-addressed reference to a file produced during a session."""
    filename: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict:
        return {"filename": self.filename, "sha256": self.sha256, "size_bytes": self.size_bytes}

    @classmethod
    def from_file(cls, path: str | Path) -> "ArtifactRef":
        p = Path(path)
        return cls(
            filename=p.name,
            sha256=sha256_file(p),
            size_bytes=p.stat().st_size,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "ArtifactRef":
        return cls(filename=d["filename"], sha256=d["sha256"], size_bytes=d["size_bytes"])


@dataclass
class TurnData:
    """Hashed representation of a single prompt/response turn."""
    prompt_hash: str
    response_hash: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    model: Optional[str] = None
    api_request_id: Optional[str] = None
    token_count: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "prompt_hash": self.prompt_hash,
            "response_hash": self.response_hash,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "model": self.model,
            "api_request_id": self.api_request_id,
            "token_count": self.token_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TurnData":
        return cls(
            prompt_hash=d["prompt_hash"],
            response_hash=d["response_hash"],
            artifacts=[ArtifactRef.from_dict(a) for a in d.get("artifacts", [])],
            model=d.get("model"),
            api_request_id=d.get("api_request_id"),
            token_count=d.get("token_count"),
        )

    @classmethod
    def from_plaintext(
        cls,
        prompt: str,
        response: str,
        artifact_paths: list[str | Path] | None = None,
        model: str | None = None,
        api_request_id: str | None = None,
        token_count: int | None = None,
    ) -> "TurnData":
        """Create TurnData by hashing plaintext content."""
        return cls(
            prompt_hash=sha256_hex(prompt.encode("utf-8")),
            response_hash=sha256_hex(response.encode("utf-8")),
            artifacts=[ArtifactRef.from_file(p) for p in (artifact_paths or [])],
            model=model,
            api_request_id=api_request_id,
            token_count=token_count,
        )


GENESIS_HASH = "GENESIS"


@dataclass
class ChainRecord:
    """A single record in the hash chain."""
    seq: int
    nonce: str
    turn: TurnData
    timestamp: str       # ISO 8601 UTC
    prev_hash: str       # GENESIS_HASH for the first record
    record_hash: str = ""  # computed after construction

    def _hashable_dict(self) -> dict:
        """The canonical representation used to compute record_hash.

        IMPORTANT: record_hash itself is NOT included — it's the output.
        """
        return {
            "seq": self.seq,
            "nonce": self.nonce,
            "turn": self.turn.to_dict(),
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self._hashable_dict()))

    def finalize(self) -> "ChainRecord":
        """Compute and set record_hash. Returns self for chaining."""
        self.record_hash = self.compute_hash()
        return self

    def to_dict(self) -> dict:
        d = self._hashable_dict()
        d["record_hash"] = self.record_hash
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ChainRecord":
        rec = cls(
            seq=d["seq"],
            nonce=d["nonce"],
            turn=TurnData.from_dict(d["turn"]),
            timestamp=d["timestamp"],
            prev_hash=d["prev_hash"],
            record_hash=d.get("record_hash", ""),
        )
        return rec


# ---------------------------------------------------------------------------
# Chain operations
# ---------------------------------------------------------------------------

class Chain:
    """An append-only hash chain of conversation records."""

    def __init__(self):
        self.records: list[ChainRecord] = []

    @property
    def head_hash(self) -> str:
        """The hash of the most recent record, or GENESIS if empty."""
        if not self.records:
            return GENESIS_HASH
        return self.records[-1].record_hash

    def append_turn(
        self,
        prompt: str,
        response: str,
        artifact_paths: list[str | Path] | None = None,
        model: str | None = None,
        api_request_id: str | None = None,
        token_count: int | None = None,
    ) -> ChainRecord:
        """Create, finalize, and append a new record from plaintext."""
        turn = TurnData.from_plaintext(
            prompt=prompt,
            response=response,
            artifact_paths=artifact_paths,
            model=model,
            api_request_id=api_request_id,
            token_count=token_count,
        )
        record = ChainRecord(
            seq=len(self.records),
            nonce=generate_nonce(),
            turn=turn,
            timestamp=datetime.now(timezone.utc).isoformat(),
            prev_hash=self.head_hash,
        ).finalize()

        self.records.append(record)
        return record

    def verify(self) -> tuple[bool, list[str]]:
        """Verify the entire chain's integrity.

        Returns (is_valid, list_of_errors).
        """
        errors = []
        for i, rec in enumerate(self.records):
            # Check record_hash matches content
            expected = rec.compute_hash()
            if rec.record_hash != expected:
                errors.append(
                    f"Record {i}: record_hash mismatch "
                    f"(expected {expected[:16]}..., got {rec.record_hash[:16]}...)"
                )

            # Check prev_hash linkage
            if i == 0:
                if rec.prev_hash != GENESIS_HASH:
                    errors.append(f"Record 0: prev_hash should be GENESIS")
            else:
                if rec.prev_hash != self.records[i - 1].record_hash:
                    errors.append(
                        f"Record {i}: prev_hash doesn't match record {i-1}'s hash"
                    )

            # Check seq is monotonic
            if rec.seq != i:
                errors.append(f"Record {i}: seq is {rec.seq}, expected {i}")

        return (len(errors) == 0, errors)

    def save(self, path: str | Path):
        """Save chain to a JSONL file (one record per line)."""
        with open(path, "w") as f:
            for rec in self.records:
                f.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> "Chain":
        """Load chain from a JSONL file."""
        chain = cls()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    chain.records.append(ChainRecord.from_dict(json.loads(line)))
        return chain
