"""
claudedeck.anchoring — Unified anchor orchestrator.

Dispatches chain head anchoring to one or more backends (local, Sigstore,
OpenTimestamps) and writes all results to a single anchor log.

The anchor log uses a uniform schema so that anchor-verify can handle
any backend without knowing which was used at signing time.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .signing import validate_hash_only


BACKENDS = ("local", "sigstore", "ots")


@dataclass
class AnchorResult:
    success: bool
    anchor_type: str
    chain_head_hash: str = ""
    reference: str = ""
    timestamp: str = ""
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)


def _log_path(deck_dir: Path) -> Path:
    return deck_dir / "anchor_log.jsonl"


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path) as f:
        return sum(1 for _ in f)


def _write_log_entry(deck_dir: Path, result: AnchorResult) -> int:
    """Append an anchor result to the unified log. Returns the log index."""
    from .core import file_lock
    log = _log_path(deck_dir)
    with file_lock(log):
        log_index = _count_lines(log)
        entry = {
            "index": log_index,
            "anchor_type": result.anchor_type,
            "chain_head_hash": result.chain_head_hash,
            "timestamp": result.timestamp,
            "reference": result.reference,
            "extra": result.extra,
        }
        try:
            from .integrity import hmac_json
            entry["_hmac"] = hmac_json(entry, deck_dir)
        except Exception:
            pass
        with open(log, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    return log_index


def read_log_entries(deck_dir: Path, chain_head_hash: str | None = None) -> list[dict]:
    """Read anchor log entries, optionally filtering by chain head hash."""
    log = _log_path(deck_dir)
    if not log.exists():
        return []
    entries = []
    with open(log) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Backward compat: old entries without anchor_type are local
            entry.setdefault("anchor_type", "local")
            entry.setdefault("reference", "")
            entry.setdefault("extra", {})
            # Verify HMAC if present
            stored_hmac = entry.pop("_hmac", None)
            if stored_hmac is not None:
                try:
                    from .integrity import verify_hmac_json
                    entry["_hmac_valid"] = verify_hmac_json(entry, stored_hmac, deck_dir)
                except Exception:
                    entry["_hmac_valid"] = None
            else:
                entry["_hmac_valid"] = None  # legacy entry
            if chain_head_hash is None or entry["chain_head_hash"] == chain_head_hash:
                entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Backend dispatch
# ---------------------------------------------------------------------------

def _anchor_local(chain_head_hash: str, deck_dir: Path) -> AnchorResult:
    from .local_anchor import sign_local

    result = sign_local(chain_head_hash, deck_dir)
    if result.success:
        return AnchorResult(
            success=True,
            anchor_type="local",
            chain_head_hash=chain_head_hash,
            reference=f"local:log_index={result.log_index},key_id={result.key_id[:16]}",
            timestamp=result.timestamp,
            extra={
                "signature": result.signature,
                "key_id": result.key_id,
                "local_log_index": result.log_index,
            },
        )
    return AnchorResult(
        success=False,
        anchor_type="local",
        chain_head_hash=chain_head_hash,
        error=result.error,
    )


def _anchor_sigstore(chain_head_hash: str, deck_dir: Path) -> AnchorResult:
    from .signing import sign_with_sigstore

    result = sign_with_sigstore(chain_head_hash)
    timestamp = datetime.now(timezone.utc).isoformat()
    if result.success:
        return AnchorResult(
            success=True,
            anchor_type="sigstore",
            chain_head_hash=chain_head_hash,
            reference=f"rekor:{result.rekor_log_index}" if result.rekor_log_index else "rekor:unknown",
            timestamp=timestamp,
            extra={
                "rekor_log_index": result.rekor_log_index,
                "rekor_url": result.rekor_url,
            },
        )
    return AnchorResult(
        success=False,
        anchor_type="sigstore",
        chain_head_hash=chain_head_hash,
        error=result.error,
    )


def _anchor_ots(chain_head_hash: str, deck_dir: Path) -> AnchorResult:
    from .signing import stamp_with_ots

    result = stamp_with_ots(chain_head_hash, output_dir=str(deck_dir))
    timestamp = datetime.now(timezone.utc).isoformat()
    if result.success:
        return AnchorResult(
            success=True,
            anchor_type="ots",
            chain_head_hash=chain_head_hash,
            reference=f"ots:{result.proof_path}",
            timestamp=timestamp,
            extra={
                "ots_proof_path": result.proof_path,
            },
        )
    return AnchorResult(
        success=False,
        anchor_type="ots",
        chain_head_hash=chain_head_hash,
        error=result.error,
    )


_DISPATCH = {
    "local": _anchor_local,
    "sigstore": _anchor_sigstore,
    "ots": _anchor_ots,
}


def anchor(chain_head_hash: str, backend: str, deck_dir: Path) -> AnchorResult:
    """Anchor a chain head hash with a single backend.

    The hash is validated through the signing airlock before dispatch.
    Results are written to the unified anchor log.
    """
    safe_hash = validate_hash_only(chain_head_hash)

    if backend not in _DISPATCH:
        return AnchorResult(
            success=False,
            anchor_type=backend,
            chain_head_hash=safe_hash,
            error=f"Unknown backend: {backend}",
        )

    # Local backend writes its own log entry; external backends go through us
    if backend == "local":
        result = _anchor_local(safe_hash, deck_dir)
        # local_anchor already wrote to anchor_log.jsonl, so don't double-write
        return result

    result = _DISPATCH[backend](safe_hash, deck_dir)
    if result.success:
        _write_log_entry(deck_dir, result)
    return result


def anchor_all(
    chain_head_hash: str,
    backends: list[str],
    deck_dir: Path,
) -> list[AnchorResult]:
    """Anchor a chain head hash with multiple backends.

    Returns results from each backend. Failures on individual backends
    do not prevent others from running.
    """
    safe_hash = validate_hash_only(chain_head_hash)
    results = []
    for backend in backends:
        result = anchor(safe_hash, backend, deck_dir)
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Verification dispatch
# ---------------------------------------------------------------------------

def verify_anchor(entry: dict, deck_dir: Path) -> tuple[bool, str]:
    """Verify an anchor log entry.

    Returns (is_valid, detail_message).
    For external backends, requires the corresponding CLI tool.
    """
    anchor_type = entry.get("anchor_type", "local")
    chain_head_hash = entry["chain_head_hash"]

    if anchor_type == "local":
        extra = entry.get("extra", {})
        signature = extra.get("signature", entry.get("signature", ""))
        timestamp = entry.get("timestamp", "")
        if not signature:
            return False, "Local anchor entry missing signature"
        from .local_anchor import verify_local, check_key_consistency
        ok, detail = verify_local(chain_head_hash, signature, timestamp, deck_dir)
        # Surface key consistency warning if signature is valid
        if ok:
            consistent, consistency_detail = check_key_consistency(deck_dir)
            if not consistent:
                detail += f" (WARNING: {consistency_detail})"
        return ok, detail

    elif anchor_type == "sigstore":
        from .signing import verify_with_sigstore
        extra = entry.get("extra", {})
        rekor_log_index = extra.get("rekor_log_index")
        if not rekor_log_index:
            return False, "Sigstore anchor entry missing rekor_log_index"
        result = verify_with_sigstore(chain_head_hash, rekor_log_index)
        if result.error and "not found" in result.error.lower():
            return False, f"cosign not available — verify manually: rekor-cli get --log-index {rekor_log_index}"
        return result.success, result.error or f"Sigstore anchor verified (rekor index {rekor_log_index})"

    elif anchor_type == "ots":
        from .signing import verify_with_ots
        extra = entry.get("extra", {})
        ots_proof_path = extra.get("ots_proof_path")
        if not ots_proof_path:
            return False, "OTS anchor entry missing ots_proof_path"
        result = verify_with_ots(chain_head_hash, ots_proof_path)
        if result.error and "not found" in result.error.lower():
            return False, f"ots not available — verify manually: ots verify {ots_proof_path}"
        return result.success, result.error or f"OTS anchor verified ({ots_proof_path})"

    else:
        return False, f"Unknown anchor type: {anchor_type}"
