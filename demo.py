#!/usr/bin/env python3
"""
demo.py — End-to-end demonstration of claudedeck.

Simulates a Claude Code session where a researcher:
1. Asks Claude to write a script
2. Gets a response + artifact (the script file)
3. Asks a follow-up question
4. Seals the session into a hash chain
5. Creates a proof bundle disclosing specific turns
6. Verifies the proof bundle
7. Shows what happens if someone tampers with the bundle
"""

import json
import os
import tempfile

from claudedeck.core import Chain, sha256_hex
from claudedeck.vault import Vault
from claudedeck.proof import (
    create_proof_bundle, verify_proof_bundle, AnchorRef
)
from claudedeck.signing import validate_hash_only


def main():
    work_dir = tempfile.mkdtemp(prefix="claudedeck_demo_")
    print(f"Working directory: {work_dir}\n")

    # =================================================================
    # STEP 1: Simulate a Claude Code session
    # =================================================================
    print("=" * 60)
    print("STEP 1: Recording a session")
    print("=" * 60)

    # Create a simulated artifact (a script Claude "wrote")
    artifact_path = os.path.join(work_dir, "analyze.py")
    artifact_content = """import numpy as np
import pandas as pd

def analyze_expression_data(csv_path: str) -> dict:
    df = pd.read_csv(csv_path)
    return {
        "mean_expression": df["expression"].mean(),
        "std_expression": df["expression"].std(),
        "n_genes": len(df),
    }

if __name__ == "__main__":
    results = analyze_expression_data("expression_data.csv")
    print(results)
"""
    with open(artifact_path, "w") as f:
        f.write(artifact_content)

    # Build the chain
    chain = Chain()

    # Turn 0: Initial prompt + response with artifact
    rec0 = chain.append_turn(
        prompt="Write a Python script to analyze gene expression data from a CSV. "
               "Calculate mean expression, standard deviation, and gene count.",
        response="Here's a script that loads a CSV and computes basic expression statistics. "
                 "I've saved it as `analyze.py`.",
        artifact_paths=[artifact_path],
        model="claude-sonnet-4-20250514",
        api_request_id="req_01ABC123DEF456",
        token_count=342,
    )
    print(f"  Record 0: seq={rec0.seq}, hash={rec0.record_hash[:24]}...")
    print(f"    Artifacts: {[a.filename for a in rec0.turn.artifacts]}")

    # Turn 1: Follow-up question
    rec1 = chain.append_turn(
        prompt="Can you add a function to identify differentially expressed genes "
               "using a simple fold-change threshold?",
        response="I've added a `find_de_genes` function that filters by fold-change. "
                 "You can set the threshold parameter — default is 2.0.",
        model="claude-sonnet-4-20250514",
        api_request_id="req_01XYZ789GHI012",
        token_count=256,
    )
    print(f"  Record 1: seq={rec1.seq}, hash={rec1.record_hash[:24]}...")

    # Turn 2: Methodological question (no artifact)
    rec2 = chain.append_turn(
        prompt="What statistical test would be more appropriate than fold-change "
               "for small sample sizes?",
        response="For small sample sizes, a moderated t-test (like limma's eBayes) "
                 "is more appropriate. It borrows information across genes to stabilize "
                 "variance estimates.",
        model="claude-sonnet-4-20250514",
        api_request_id="req_01QRS345TUV678",
        token_count=189,
    )
    print(f"  Record 2: seq={rec2.seq}, hash={rec2.record_hash[:24]}...")

    # Verify chain
    is_valid, errors = chain.verify()
    print(f"\n  Chain integrity: {'VALID' if is_valid else 'INVALID'}")
    print(f"  Chain head: {chain.head_hash[:32]}...")

    # Save chain
    chain_path = os.path.join(work_dir, "session.chain.jsonl")
    chain.save(chain_path)
    print(f"  Chain saved to: {chain_path}")

    # =================================================================
    # STEP 2: Store plaintext in encrypted vault
    # =================================================================
    print(f"\n{'=' * 60}")
    print("STEP 2: Encrypting plaintext in vault")
    print("=" * 60)

    vault_path = os.path.join(work_dir, "session.vault")
    vault = Vault(vault_path, passphrase="demo-passphrase-change-me")

    vault.store(0,
        prompt="Write a Python script to analyze gene expression data from a CSV. "
               "Calculate mean expression, standard deviation, and gene count.",
        response="Here's a script that loads a CSV and computes basic expression statistics. "
                 "I've saved it as `analyze.py`.",
        artifacts={"analyze.py": artifact_content},
    )
    vault.store(1,
        prompt="Can you add a function to identify differentially expressed genes "
               "using a simple fold-change threshold?",
        response="I've added a `find_de_genes` function that filters by fold-change. "
                 "You can set the threshold parameter — default is 2.0.",
    )
    vault.store(2,
        prompt="What statistical test would be more appropriate than fold-change "
               "for small sample sizes?",
        response="For small sample sizes, a moderated t-test (like limma's eBayes) "
                 "is more appropriate. It borrows information across genes to stabilize "
                 "variance estimates.",
    )
    vault.save()
    print(f"  Vault encrypted and saved to: {vault_path}")
    print(f"  Vault file size: {os.path.getsize(vault_path)} bytes")

    # =================================================================
    # STEP 3: Hash-only signing boundary demo
    # =================================================================
    print(f"\n{'=' * 60}")
    print("STEP 3: Signing boundary (airlock)")
    print("=" * 60)

    # This should succeed — it's a valid hash
    safe = validate_hash_only(chain.head_hash)
    print(f"  Valid hash accepted: {safe[:24]}...")

    # This should fail — attempting to pass content through the airlock
    try:
        validate_hash_only("This is not a hash, it's prompt text that should never leave the machine!")
    except ValueError as e:
        print(f"  Content blocked: {str(e)[:80]}...")

    print(f"\n  Only the 64-char hex digest ever reaches external services.")
    print(f"  Sigstore/OTS would receive: {chain.head_hash}")
    print(f"  Nothing else.")

    # =================================================================
    # STEP 4: Create proof bundle (selective disclosure)
    # =================================================================
    print(f"\n{'=' * 60}")
    print("STEP 4: Creating proof bundle")
    print("=" * 60)

    # Researcher discloses turns 0 and 2, but NOT turn 1
    # (maybe turn 1 contained proprietary method details)
    bundle = create_proof_bundle(
        chain=chain,
        vault=vault,
        disclose_seqs=[0, 2],
        anchors=[
            AnchorRef(
                anchor_type="sigstore",
                chain_head_hash=chain.head_hash,
                reference="rekor-log-index-12345678 (simulated)",
                timestamp="2026-03-15T12:00:00Z",
            ),
            AnchorRef(
                anchor_type="opentimestamps",
                chain_head_hash=chain.head_hash,
                reference="session_head.sha256.ots (simulated)",
                timestamp="2026-03-15T12:00:00Z",
            ),
        ],
        metadata={
            "researcher": "Dr. Jane Smith",
            "orcid": "0000-0002-1234-5678",
            "purpose": "Demonstrating AI-assisted gene expression analysis workflow",
            "institution": "University of Example",
        },
    )

    bundle_path = os.path.join(work_dir, "proof_bundle.json")
    bundle.save(bundle_path)
    print(f"  Bundle saved to: {bundle_path}")
    print(f"  Disclosed turns: 0 and 2 (turn 1 is redacted)")
    print(f"  Turn 1 exists in chain as hash only — proves it happened,")
    print(f"  but its content remains private.")

    # =================================================================
    # STEP 5: Verify the proof bundle
    # =================================================================
    print(f"\n{'=' * 60}")
    print("STEP 5: Verification (as an auditor would do)")
    print("=" * 60)

    from claudedeck.proof import ProofBundle as PB
    loaded_bundle = PB.load(bundle_path)
    result = verify_proof_bundle(loaded_bundle)
    print(result.summary())

    # =================================================================
    # STEP 6: Demonstrate tamper detection
    # =================================================================
    print(f"\n{'=' * 60}")
    print("STEP 6: Tamper detection demo")
    print("=" * 60)

    # Load the bundle, tamper with a response, and re-verify
    with open(bundle_path) as f:
        tampered = json.load(f)

    original_response = tampered["disclosed_turns"][0]["response"]
    tampered["disclosed_turns"][0]["response"] = (
        "I wrote a completely different script that does something else. "
        "(This response has been tampered with.)"
    )

    tampered_path = os.path.join(work_dir, "tampered_bundle.json")
    with open(tampered_path, "w") as f:
        json.dump(tampered, f, indent=2)

    tampered_bundle = PB.load(tampered_path)
    tampered_result = verify_proof_bundle(tampered_bundle)
    print(tampered_result.summary())

    # =================================================================
    # Summary
    # =================================================================
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"""
  Files produced:
    {chain_path}       — Hash chain (safe to publish)
    {vault_path}        — Encrypted vault (keep private)
    {bundle_path}    — Proof bundle (share with auditors)
    {artifact_path}        — Artifact (the script Claude "wrote")

  What a researcher publishes:
    1. The proof bundle JSON
    2. The artifact files
    3. verify_proof.py (so anyone can check)

  What stays private:
    - The encrypted vault (full session plaintext)
    - Turn 1's content (redacted from the proof bundle)

  What an auditor can verify:
    - The chain is internally consistent (no insertions/deletions)
    - Disclosed prompts hash-match the chain records
    - Disclosed responses hash-match the chain records
    - The artifact file hash-matches the chain record
    - The chain head was anchored at a specific time (Sigstore + OTS)
    - Even redacted turns are accounted for in the chain
    """)


if __name__ == "__main__":
    main()
