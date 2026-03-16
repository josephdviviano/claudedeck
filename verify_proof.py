#!/usr/bin/env python3
"""
verify_proof.py — Standalone proof bundle verifier.

ZERO EXTERNAL DEPENDENCIES. Uses only Python stdlib.
Anyone can verify a proof bundle without installing the claudedeck package.

Usage:
    python verify_proof.py bundle.proof.json
    python verify_proof.py bundle.proof.json --verbose
    python verify_proof.py bundle.proof.json --check-artifact path/to/file.py

This script verifies:
  1. The hash chain is internally consistent (no tampering)
  2. Disclosed prompts/responses match their chain hashes
  3. Disclosed artifacts match their chain hashes
  4. (Optional) A local artifact file matches the chain record
"""

import hashlib
import json
import sys
from pathlib import Path


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_chain(records: list[dict]) -> tuple[bool, list[str]]:
    """Verify the hash chain's internal consistency."""
    errors = []
    for i, rec in enumerate(records):
        # Recompute record hash
        hashable = {
            "seq": rec["seq"],
            "nonce": rec["nonce"],
            "turn": rec["turn"],
            "timestamp": rec["timestamp"],
            "prev_hash": rec["prev_hash"],
        }
        expected = sha256_hex(canonical_json(hashable))
        if rec["record_hash"] != expected:
            errors.append(f"Record {i} (seq {rec['seq']}): hash mismatch")

        # Check linkage
        if i == 0:
            if rec["prev_hash"] != "GENESIS":
                errors.append(f"Record 0: prev_hash should be GENESIS")
        else:
            if rec["prev_hash"] != records[i - 1]["record_hash"]:
                errors.append(f"Record {i}: broken link to record {i-1}")

    return len(errors) == 0, errors


def verify_disclosures(records: list[dict], disclosed: list[dict]) -> tuple[bool, list[str]]:
    """Verify disclosed content matches chain hashes."""
    errors = []
    record_by_seq = {r["seq"]: r for r in records}

    for turn in disclosed:
        seq = turn["seq"]
        rec = record_by_seq.get(seq)
        if rec is None:
            errors.append(f"Disclosed seq {seq}: no matching chain record")
            continue

        # Verify prompt hash
        prompt_hash = sha256_hex(turn["prompt"].encode("utf-8"))
        if prompt_hash != rec["turn"]["prompt_hash"]:
            errors.append(f"Seq {seq}: PROMPT HASH MISMATCH")
        
        # Verify response hash
        response_hash = sha256_hex(turn["response"].encode("utf-8"))
        if response_hash != rec["turn"]["response_hash"]:
            errors.append(f"Seq {seq}: RESPONSE HASH MISMATCH")

        # Verify disclosed artifacts
        chain_artifacts = {a["filename"]: a["sha256"] for a in rec["turn"].get("artifacts", [])}
        for filename, content in turn.get("artifacts", {}).items():
            expected = chain_artifacts.get(filename)
            if expected is None:
                errors.append(f"Seq {seq}: artifact '{filename}' not in chain record")
            elif sha256_hex(content.encode("utf-8")) != expected:
                errors.append(f"Seq {seq}: ARTIFACT '{filename}' HASH MISMATCH")

    return len(errors) == 0, errors


def verify_local_artifact(records: list[dict], filepath: str) -> tuple[bool, str]:
    """Check if a local file matches any artifact hash in the chain."""
    p = Path(filepath)
    if not p.exists():
        return False, f"File not found: {filepath}"

    file_hash = sha256_hex(p.read_bytes())
    filename = p.name

    for rec in records:
        for artifact in rec["turn"].get("artifacts", []):
            if artifact["filename"] == filename and artifact["sha256"] == file_hash:
                return True, (
                    f"MATCH: {filename} matches artifact in chain record "
                    f"seq {rec['seq']} (hash: {file_hash[:16]}...)"
                )

    return False, f"NO MATCH: {filename} (hash: {file_hash[:16]}...) not found in any chain record"


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_proof.py <bundle.proof.json> [--verbose] [--check-artifact FILE]")
        sys.exit(1)

    bundle_path = sys.argv[1]
    verbose = "--verbose" in sys.argv
    
    artifact_check = None
    if "--check-artifact" in sys.argv:
        idx = sys.argv.index("--check-artifact")
        if idx + 1 < len(sys.argv):
            artifact_check = sys.argv[idx + 1]

    with open(bundle_path) as f:
        bundle = json.load(f)

    print(f"=== Proof Bundle Verification ===")
    print(f"Bundle version: {bundle.get('version', 'unknown')}")
    print(f"Chain records:  {len(bundle.get('chain_records', []))}")
    print(f"Disclosed turns: {len(bundle.get('disclosed_turns', []))}")
    print(f"Anchors:        {len(bundle.get('anchors', []))}")

    if bundle.get("metadata"):
        print(f"\nMetadata:")
        for k, v in bundle["metadata"].items():
            print(f"  {k}: {v}")

    records = bundle.get("chain_records", [])
    disclosed = bundle.get("disclosed_turns", [])

    # 1. Chain integrity
    print(f"\n--- Chain Integrity ---")
    chain_ok, chain_errors = verify_chain(records)
    if chain_ok:
        print(f"  [PASS] All {len(records)} records internally consistent and linked")
        if records:
            print(f"  Chain head: {records[-1]['record_hash'][:32]}...")
    else:
        for err in chain_errors:
            print(f"  [FAIL] {err}")

    # 2. Content verification
    print(f"\n--- Content Verification ---")
    if not disclosed:
        print(f"  [INFO] No turns disclosed in this bundle")
    else:
        content_ok, content_errors = verify_disclosures(records, disclosed)
        if content_ok:
            for turn in disclosed:
                seq = turn["seq"]
                prompt_preview = turn["prompt"][:60].replace("\n", " ")
                n_artifacts = len(turn.get("artifacts", {}))
                print(f"  [PASS] Seq {seq}: prompt + response match chain hashes")
                if verbose:
                    print(f"         Prompt: \"{prompt_preview}...\"")
                if n_artifacts:
                    print(f"         {n_artifacts} artifact(s) verified")
        else:
            for err in content_errors:
                print(f"  [FAIL] {err}")

    # 3. Anchors
    print(f"\n--- External Anchors ---")
    anchors = bundle.get("anchors", [])
    if not anchors:
        print(f"  [INFO] No external anchors. Chain is self-consistent but unanchored.")
    else:
        head_hash = records[-1]["record_hash"] if records else ""
        for anchor in anchors:
            hash_ok = anchor["chain_head_hash"] == head_hash
            status = "PASS" if hash_ok else "FAIL"
            print(f"  [{status}] {anchor['anchor_type']}: references chain head")
            if verbose:
                print(f"         Ref: {anchor['reference']}")
            if not hash_ok:
                print(f"         WARNING: Anchor hash doesn't match chain head")
        print(f"  [NOTE] Verify anchors externally:")
        print(f"         Sigstore: rekor-cli get --log-index <index>")
        print(f"         OTS:     ots verify <proof.ots>")

    # 4. Optional: check local artifact
    if artifact_check:
        print(f"\n--- Local Artifact Check ---")
        ok, msg = verify_local_artifact(records, artifact_check)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {msg}")

    # Final verdict
    all_ok = chain_ok and (not disclosed or content_ok)
    print(f"\n{'='*40}")
    if all_ok:
        print("VERDICT: VALID — Chain is internally consistent and disclosed content matches.")
    else:
        print("VERDICT: INVALID — Verification failures detected. See above.")
    print(f"{'='*40}")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
