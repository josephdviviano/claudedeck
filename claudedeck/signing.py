"""
claudedeck.signing — Hash-only signing boundary.

SECURITY-CRITICAL MODULE.

This is the "airlock" between the chain and external signing services.
It enforces structurally that ONLY fixed-length hashes ever reach
Sigstore, OpenTimestamps, or any external service.

No plaintext, no metadata, no filenames — just 64 hex characters.
"""

import re
import subprocess
import shutil
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# The airlock
# ---------------------------------------------------------------------------

_HEX64_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")


def validate_hash_only(value: str) -> str:
    """Enforce that a value is exactly a SHA-256 hex digest.

    This is the ONLY function that should be called before passing
    data to any external signing service. If this function doesn't
    raise, the value is safe to publish.

    Raises:
        ValueError: If the value is not a valid SHA-256 hex string.
    """
    if not isinstance(value, str):
        raise ValueError(f"Expected str, got {type(value).__name__}")
    if not _HEX64_PATTERN.match(value):
        raise ValueError(
            f"Value is not a valid SHA-256 hex digest (got {len(value)} chars). "
            f"REFUSING to send to external service. "
            f"This may indicate accidental content leakage."
        )
    return value


# ---------------------------------------------------------------------------
# Sigstore integration
# ---------------------------------------------------------------------------

@dataclass
class SigstoreResult:
    success: bool
    rekor_log_index: Optional[str] = None
    rekor_url: Optional[str] = None
    error: Optional[str] = None


def verify_with_sigstore(chain_head_hash: str, rekor_log_index: str) -> SigstoreResult:
    """Verify a Sigstore anchor by checking the Rekor transparency log.

    Args:
        chain_head_hash: SHA-256 hex digest that was signed.
        rekor_log_index: The Rekor log index from the original signing.

    Requires: cosign CLI installed.
    """
    safe_hash = validate_hash_only(chain_head_hash)

    if not shutil.which("cosign"):
        return SigstoreResult(success=False, error="cosign not found in PATH")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sha256", delete=False) as f:
        f.write(safe_hash)
        tmp_path = f.name

    try:
        cmd = [
            "cosign", "verify-blob", tmp_path,
            "--rekor-url", "https://rekor.sigstore.dev",
            "--log-index", str(rekor_log_index),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return SigstoreResult(
                success=True,
                rekor_log_index=str(rekor_log_index),
            )
        else:
            return SigstoreResult(success=False, error=result.stderr[:500])
    finally:
        os.unlink(tmp_path)


def sign_with_sigstore(chain_head_hash: str, identity_token: str | None = None) -> SigstoreResult:
    """Sign a chain head hash using Sigstore cosign.

    The hash is written to a temporary file and signed. The file contains
    ONLY the 64-char hex digest — nothing else.

    Args:
        chain_head_hash: SHA-256 hex digest of the chain head.
        identity_token: Optional OIDC token. If None, cosign will
                        open a browser for interactive auth.

    Requires: cosign CLI installed (https://docs.sigstore.dev/cosign/installation/)
    """
    safe_hash = validate_hash_only(chain_head_hash)

    if not shutil.which("cosign"):
        return SigstoreResult(success=False, error="cosign not found in PATH")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sha256", delete=False) as f:
        f.write(safe_hash)
        tmp_path = f.name

    try:
        cmd = ["cosign", "sign-blob", "--yes", tmp_path]
        if identity_token:
            cmd.extend(["--identity-token", identity_token])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            # Parse Rekor log index from stderr (cosign prints it there)
            log_index = None
            for line in result.stderr.splitlines():
                if "tlog entry created with index" in line.lower():
                    parts = line.strip().split()
                    log_index = parts[-1] if parts else None

            return SigstoreResult(
                success=True,
                rekor_log_index=log_index,
                rekor_url=f"https://search.sigstore.dev/?logIndex={log_index}" if log_index else None,
            )
        else:
            return SigstoreResult(success=False, error=result.stderr[:500])
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# OpenTimestamps integration
# ---------------------------------------------------------------------------

@dataclass
class OTSResult:
    success: bool
    proof_path: Optional[str] = None
    error: Optional[str] = None


def stamp_with_ots(chain_head_hash: str, output_dir: str = ".") -> OTSResult:
    """Timestamp a chain head hash using OpenTimestamps.

    Args:
        chain_head_hash: SHA-256 hex digest of the chain head.
        output_dir: Directory for the .ots proof file.

    Requires: ots CLI installed (pip install opentimestamps-client)
    """
    safe_hash = validate_hash_only(chain_head_hash)

    if not shutil.which("ots"):
        return OTSResult(success=False, error="ots not found in PATH")

    import tempfile, os
    # OTS stamps files, so we create a file containing just the hash
    hash_file = os.path.join(output_dir, f"{safe_hash[:16]}.sha256")
    with open(hash_file, "w") as f:
        f.write(safe_hash)

    try:
        result = subprocess.run(
            ["ots", "stamp", hash_file],
            capture_output=True, text=True, timeout=60,
        )
        proof_path = hash_file + ".ots"
        if result.returncode == 0 and os.path.exists(proof_path):
            return OTSResult(success=True, proof_path=proof_path)
        else:
            return OTSResult(success=False, error=result.stderr[:500])
    except Exception as e:
        return OTSResult(success=False, error=str(e))


def verify_with_ots(chain_head_hash: str, ots_proof_path: str) -> OTSResult:
    """Verify an OpenTimestamps proof.

    Args:
        chain_head_hash: SHA-256 hex digest that was timestamped.
        ots_proof_path: Path to the .ots proof file.

    Requires: ots CLI installed (pip install opentimestamps-client).
    """
    safe_hash = validate_hash_only(chain_head_hash)

    if not shutil.which("ots"):
        return OTSResult(success=False, error="ots not found in PATH")

    import os
    # The .ots file corresponds to a .sha256 file containing the hash
    hash_file = ots_proof_path.replace(".ots", "")
    if not os.path.exists(hash_file):
        # Recreate the hash file so ots verify can check it
        with open(hash_file, "w") as f:
            f.write(safe_hash)

    try:
        result = subprocess.run(
            ["ots", "verify", ots_proof_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return OTSResult(success=True, proof_path=ots_proof_path)
        else:
            return OTSResult(success=False, error=result.stderr[:500])
    except Exception as e:
        return OTSResult(success=False, error=str(e))


# ---------------------------------------------------------------------------
# Combined anchoring
# ---------------------------------------------------------------------------

def anchor_chain_head(
    chain_head_hash: str,
    use_sigstore: bool = True,
    use_ots: bool = True,
    ots_output_dir: str = ".",
) -> dict:
    """Anchor a chain head hash to both Sigstore and OpenTimestamps.

    Returns a dict with results from each service.
    """
    safe_hash = validate_hash_only(chain_head_hash)

    results = {}
    if use_sigstore:
        results["sigstore"] = sign_with_sigstore(safe_hash)
    if use_ots:
        results["ots"] = stamp_with_ots(safe_hash, output_dir=ots_output_dir)
    return results
