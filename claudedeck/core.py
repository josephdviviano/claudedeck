"""
claudedeck.core — Hash chain data model and operations.

Zero external dependencies (stdlib only) so that verification
never requires trusting third-party code.
"""

import fcntl
import hashlib
import json
import os
import secrets
import tempfile
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# File safety primitives
# ---------------------------------------------------------------------------

class ChainCorruptedError(Exception):
    """Raised when attempting to save a chain that fails verification."""
    pass


def atomic_write(path: str | Path, data, mode: str = "w"):
    """Write data to path atomically via temp file + os.replace().

    If the process crashes mid-write, the original file is untouched.
    ``data`` may be a string/bytes or a callable(f) for streaming writes.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, mode) as f:
            if callable(data):
                data(f)
            else:
                f.write(data)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextmanager
def file_lock(path: str | Path):
    """Advisory exclusive file lock (POSIX only).

    Use around critical sections that read-modify-write shared files
    to prevent concurrent corruption.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


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


def _normalize_unicode(obj):
    """Recursively NFC-normalize all string values and keys."""
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {_normalize_unicode(k): _normalize_unicode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_unicode(item) for item in obj]
    return obj


def canonical_json(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing.

    Rules: NFC-normalize all strings, sorted keys, no whitespace,
    ensure_ascii=True.  Any two implementations following these rules
    will produce identical bytes for the same logical object.
    """
    normalized = _normalize_unicode(obj)
    return json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def generate_nonce(nbytes: int = 32) -> str:
    """Generate a cryptographically random nonce (hex-encoded)."""
    return secrets.token_hex(nbytes)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ArtifactRef:
    """A content-addressed reference to a file produced during a session.

    Attribution values:
        "claude:Write"          — file created/overwritten by Claude's Write tool
        "claude:Edit"           — file modified by Claude's Edit tool
        "claude:Bash(inferred)" — file changed during a turn with a Bash tool call
        "unattributed"          — file changed with no matching tool call (likely user)
        "user:declared"         — user explicitly tracked via `claudedeck track`
        "user:script"           — user tracked as script output via `claudedeck track --source script`
        "unknown"               — legacy records without attribution
    """
    filename: str
    sha256: str
    size_bytes: int
    attribution: str = "unknown"
    source_tool_id: Optional[str] = None
    filepath: Optional[str] = None   # relative path from project root

    def to_dict(self) -> dict:
        d = {
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "attribution": self.attribution,
        }
        if self.filepath is not None:
            d["filepath"] = self.filepath
        if self.source_tool_id is not None:
            d["source_tool_id"] = self.source_tool_id
        return d

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        attribution: str = "unknown",
        source_tool_id: str | None = None,
        project_root: str | Path | None = None,
    ) -> "ArtifactRef":
        p = Path(path).resolve()
        filepath = None
        if project_root is not None:
            try:
                filepath = str(p.relative_to(Path(project_root).resolve()))
            except ValueError:
                filepath = p.name
        return cls(
            filename=p.name,
            sha256=sha256_file(p),
            size_bytes=p.stat().st_size,
            attribution=attribution,
            source_tool_id=source_tool_id,
            filepath=filepath,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "ArtifactRef":
        return cls(
            filename=d["filename"],
            sha256=d["sha256"],
            size_bytes=d["size_bytes"],
            attribution=d.get("attribution", "unknown"),
            source_tool_id=d.get("source_tool_id"),
            filepath=d.get("filepath"),
        )


@dataclass
class TurnData:
    """Hashed representation of a single prompt/response turn."""
    prompt_hash: str
    response_hash: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)
    model: Optional[str] = None
    api_request_id: Optional[str] = None
    token_count: Optional[int] = None

    def to_dict(self) -> dict:
        d = {
            "prompt_hash": self.prompt_hash,
            "response_hash": self.response_hash,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "model": self.model,
            "api_request_id": self.api_request_id,
            "token_count": self.token_count,
        }
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "TurnData":
        return cls(
            prompt_hash=d["prompt_hash"],
            response_hash=d["response_hash"],
            artifacts=[ArtifactRef.from_dict(a) for a in d.get("artifacts", [])],
            tool_calls=d.get("tool_calls", []),
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
        artifacts: list["ArtifactRef"] | None = None,
        tool_calls: list[str] | None = None,
        model: str | None = None,
        api_request_id: str | None = None,
        token_count: int | None = None,
    ) -> "TurnData":
        """Create TurnData by hashing plaintext content."""
        arts = list(artifacts or [])
        if artifact_paths:
            arts.extend(ArtifactRef.from_file(p) for p in artifact_paths)
        return cls(
            prompt_hash=sha256_hex(prompt.encode("utf-8")),
            response_hash=sha256_hex(response.encode("utf-8")),
            artifacts=arts,
            tool_calls=tool_calls or [],
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
    chain_id: Optional[str] = None  # binds record to its containing chain

    def _hashable_dict(self) -> dict:
        """The canonical representation used to compute record_hash.

        IMPORTANT: record_hash itself is NOT included — it's the output.
        chain_id is included only when set (backward compat with old chains).
        """
        d = {
            "seq": self.seq,
            "nonce": self.nonce,
            "turn": self.turn.to_dict(),
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }
        if self.chain_id is not None:
            d["chain_id"] = self.chain_id
        return d

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
            chain_id=d.get("chain_id"),
        )
        return rec


# ---------------------------------------------------------------------------
# Chain operations
# ---------------------------------------------------------------------------

class Chain:
    """An append-only hash chain of conversation records."""

    def __init__(self, chain_id: str | None = None):
        self.records: list[ChainRecord] = []
        self.chain_id: str = chain_id or generate_nonce(16)

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
        artifacts: list[ArtifactRef] | None = None,
        tool_calls: list[str] | None = None,
        model: str | None = None,
        api_request_id: str | None = None,
        token_count: int | None = None,
    ) -> ChainRecord:
        """Create, finalize, and append a new record from plaintext."""
        turn = TurnData.from_plaintext(
            prompt=prompt,
            response=response,
            artifact_paths=artifact_paths,
            artifacts=artifacts,
            tool_calls=tool_calls,
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
            chain_id=self.chain_id,
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
        """Save chain to a JSONL file. Raises ChainCorruptedError if invalid."""
        if self.records:
            valid, errors = self.verify()
            if not valid:
                raise ChainCorruptedError(
                    f"Refusing to save corrupted chain: {'; '.join(errors)}"
                )

        def _write(f):
            # Metadata preamble
            meta = {"_meta": True, "chain_id": self.chain_id, "version": "0.2.0"}
            f.write(json.dumps(meta, sort_keys=True) + "\n")
            for rec in self.records:
                f.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")
        atomic_write(path, _write)

    @classmethod
    def load(cls, path: str | Path) -> "Chain":
        """Load chain from a JSONL file.

        Skips malformed lines with a stderr warning instead of crashing.
        Reads an optional metadata preamble for chain_id and version.
        """
        chain = cls.__new__(cls)
        chain.records = []
        chain.chain_id = None

        import sys
        with open(path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if d.get("_meta"):
                        chain.chain_id = d.get("chain_id")
                        continue
                    rec = ChainRecord.from_dict(d)
                    chain.records.append(rec)
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    print(
                        f"claudedeck: WARNING: skipping malformed line {line_num} "
                        f"in {path}: {e}",
                        file=sys.stderr,
                    )

        # Assign a retroactive chain_id if the file predates this feature
        if chain.chain_id is None:
            chain.chain_id = generate_nonce(16)

        return chain
