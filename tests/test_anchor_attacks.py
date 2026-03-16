"""
tests/test_anchor_attacks.py — Anchor trust model attack tests.

Tests for local anchor key manipulation, anchor log tampering,
and the gap between "hash existed" and "content existed" proofs.

Audit refs: C4 (key regeneration), C5 (content swap before anchor),
C6 (retroactive chain+log edit), C7 (no file locking)
"""

import json
from pathlib import Path

import pytest

from claudedeck.core import Chain, sha256_hex, canonical_json, generate_nonce
from claudedeck.local_anchor import (
    sign_local, verify_local, verify_from_log,
    _load_or_create_key, _key_path, _log_path,
)
from claudedeck.anchoring import (
    anchor, read_log_entries, verify_anchor, _write_log_entry, AnchorResult,
)
from claudedeck.proof import (
    ProofBundle, DisclosedTurn, AnchorRef, verify_proof_bundle,
)


# ---------------------------------------------------------------------------
# VULNERABILITY: Local anchor key regeneration (C4)
# ---------------------------------------------------------------------------

class TestLocalKeyRegeneration:
    """The local anchor key can be deleted and regenerated,
    allowing an attacker to forge signatures."""

    def test_key_regenerates_on_deletion(self, tmp_path):
        """VULNERABILITY: Deleting the key file causes a new key to be created."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        key1, kid1 = _load_or_create_key(deck_dir)
        key_file = _key_path(deck_dir)
        assert key_file.exists()

        # Delete the key
        key_file.unlink()

        # New key is auto-generated
        key2, kid2 = _load_or_create_key(deck_dir)
        assert key1 != key2, "New key generated after deletion"
        assert kid1 != kid2, "Key ID changed"

    def test_forged_signature_with_regenerated_key(self, tmp_path):
        """VULNERABILITY: After key regeneration, attacker can sign any hash.

        Attack flow:
        1. Create chain, anchor with original key
        2. Delete key file
        3. Modify chain content, recompute hashes
        4. Sign with new key
        5. verify_local uses the NEW key and succeeds
        """
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        # Step 1: Create and anchor a chain
        original_hash = sha256_hex(b"original content")
        result1 = sign_local(original_hash, deck_dir)
        assert result1.success

        # Verify with original key works
        ok1, _ = verify_local(original_hash, result1.signature, result1.timestamp, deck_dir)
        assert ok1

        # Step 2: Delete the key
        _key_path(deck_dir).unlink()

        # Step 3: Sign a DIFFERENT hash with the new key
        forged_hash = sha256_hex(b"forged content")
        result2 = sign_local(forged_hash, deck_dir)
        assert result2.success

        # Step 4: Verify the forged signature with the new key
        ok2, _ = verify_local(forged_hash, result2.signature, result2.timestamp, deck_dir)
        assert ok2, "Forged signature verifies with regenerated key"

        # The old signature no longer verifies (key changed)
        ok_old, _ = verify_local(original_hash, result1.signature, result1.timestamp, deck_dir)
        assert ok_old is False, "Original signature invalidated by key change"

    def test_key_id_mismatch_detectable(self, tmp_path):
        """DEFENSE OPPORTUNITY: key_id changes are detectable.

        If we store the original key_id in the anchor log entry,
        key regeneration can be detected by comparing key_ids.
        """
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        _, kid1 = _load_or_create_key(deck_dir)
        result1 = sign_local(sha256_hex(b"test"), deck_dir)

        _key_path(deck_dir).unlink()

        _, kid2 = _load_or_create_key(deck_dir)
        assert kid1 != kid2, "Key IDs differ after regeneration"

        # The log entry from result1 has the OLD key_id
        log = _log_path(deck_dir)
        entries = []
        with open(log) as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        # First entry has original key_id, can be compared to current
        assert entries[0]["key_id"] == kid1
        assert entries[0]["key_id"] != kid2


# ---------------------------------------------------------------------------
# VULNERABILITY: Anchor log tampering (C6)
# ---------------------------------------------------------------------------

class TestAnchorLogTampering:
    """The anchor log is a JSONL file with no integrity protection."""

    def test_anchor_log_entries_editable(self, tmp_path):
        """VULNERABILITY: Anchor log entries can be modified on disk."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        original_hash = sha256_hex(b"original")
        result = sign_local(original_hash, deck_dir)
        assert result.success

        log = _log_path(deck_dir)
        content = log.read_text()

        # Attacker modifies the chain_head_hash in the log entry
        forged_hash = sha256_hex(b"forged")
        modified = content.replace(original_hash, forged_hash)
        log.write_text(modified)

        # Log now contains the forged hash
        entries = read_log_entries(deck_dir, chain_head_hash=forged_hash)
        assert len(entries) == 1
        assert entries[0]["chain_head_hash"] == forged_hash

    def test_chain_and_anchor_both_modified_consistently(self, tmp_path):
        """VULNERABILITY: Modifying both chain and anchor log together
        produces a consistent but forged state.

        Attack: Modify chain content, recompute hashes, update anchor
        log to reference the new head hash, re-sign with current key.
        """
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        # Create original chain and anchor
        chain = Chain()
        chain.append_turn(prompt="original prompt", response="original response")

        result = sign_local(chain.head_hash, deck_dir)
        assert result.success

        # Verify original state
        ok, _ = verify_from_log(chain.head_hash, result.log_index, deck_dir)
        assert ok

        # Attacker creates a new chain with different content
        forged_chain = Chain()
        forged_chain.append_turn(prompt="FORGED prompt", response="FORGED response")

        # Re-sign with current key
        forged_result = sign_local(forged_chain.head_hash, deck_dir)
        assert forged_result.success

        # Forged chain + new anchor verify correctly
        ok2, _ = verify_from_log(
            forged_chain.head_hash, forged_result.log_index, deck_dir
        )
        assert ok2, "Forged chain with new anchor verifies"

    def test_anchor_log_entry_injection(self, tmp_path):
        """VULNERABILITY: Extra entries can be appended to anchor log."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        # Create a legitimate anchor
        real_hash = sha256_hex(b"real")
        sign_local(real_hash, deck_dir)

        # Inject a fake entry
        fake_entry = {
            "index": 1,
            "chain_head_hash": sha256_hex(b"fake"),
            "timestamp": "2026-03-16T00:00:00Z",
            "signature": "f" * 64,
            "key_id": "0" * 64,
        }
        log = _log_path(deck_dir)
        with open(log, "a") as f:
            f.write(json.dumps(fake_entry, sort_keys=True) + "\n")

        # Injected entry appears in log
        entries = read_log_entries(deck_dir)
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# VULNERABILITY: Content swap before anchoring (C5)
# ---------------------------------------------------------------------------

class TestContentSwapBeforeAnchoring:
    """There is a time gap between chain creation and anchoring.
    Content can be modified in this window."""

    def test_modify_chain_then_anchor(self, tmp_path):
        """VULNERABILITY: Chain can be replaced before anchoring.

        Timeline:
        1. Hook creates chain with content A
        2. User modifies chain file to content B (recalculates hashes)
        3. User anchors the modified chain
        4. Anchor verifies against content B, not A
        """
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        # Step 1: Create original chain
        original_chain = Chain()
        original_chain.append_turn(prompt="real prompt", response="real response")
        chain_path = deck_dir / "test.chain.jsonl"
        original_chain.save(chain_path)

        # Step 2: Attacker creates replacement chain
        forged_chain = Chain()
        forged_chain.append_turn(prompt="forged prompt", response="forged response")
        forged_chain.save(chain_path)  # Overwrites original

        # Step 3: Anchor the forged chain
        result = sign_local(forged_chain.head_hash, deck_dir)
        assert result.success

        # Step 4: Forged chain verifies
        loaded = Chain.load(chain_path)
        valid, _ = loaded.verify()
        assert valid is True

        ok, _ = verify_from_log(loaded.head_hash, result.log_index, deck_dir)
        assert ok, "Forged chain anchored and verified successfully"

        # Original content is gone
        assert loaded.records[0].turn.prompt_hash != original_chain.records[0].turn.prompt_hash


# ---------------------------------------------------------------------------
# Anchor verification edge cases
# ---------------------------------------------------------------------------

class TestAnchorVerificationEdgeCases:

    def test_verify_with_missing_key_file(self, tmp_path):
        """DEFENSE: Verification fails gracefully when key is missing."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        ok, detail = verify_local(
            "a" * 64, "b" * 64, "2026-03-16T00:00:00Z", deck_dir
        )
        assert ok is False
        assert "not found" in detail.lower()

    def test_verify_with_wrong_signature(self, tmp_path):
        """DEFENSE: Wrong signature is rejected."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        test_hash = sha256_hex(b"test")
        result = sign_local(test_hash, deck_dir)

        ok, detail = verify_local(
            test_hash, "wrong" + "0" * 59, result.timestamp, deck_dir
        )
        assert ok is False
        assert "INVALID" in detail

    def test_verify_with_wrong_timestamp(self, tmp_path):
        """DEFENSE: Changed timestamp invalidates signature."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        test_hash = sha256_hex(b"test")
        result = sign_local(test_hash, deck_dir)

        ok, detail = verify_local(
            test_hash, result.signature, "2020-01-01T00:00:00Z", deck_dir
        )
        assert ok is False

    def test_verify_with_wrong_hash(self, tmp_path):
        """DEFENSE: Changed hash invalidates signature."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        test_hash = sha256_hex(b"test")
        result = sign_local(test_hash, deck_dir)

        different_hash = sha256_hex(b"different")
        ok, detail = verify_local(
            different_hash, result.signature, result.timestamp, deck_dir
        )
        assert ok is False

    def test_verify_from_log_nonexistent_index(self, tmp_path):
        """DEFENSE: Requesting a non-existent log index fails."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        sign_local(sha256_hex(b"test"), deck_dir)

        ok, detail = verify_from_log(sha256_hex(b"test"), 999, deck_dir)
        assert ok is False
        assert "not found" in detail.lower()

    def test_verify_unknown_anchor_type(self, tmp_path):
        """DEFENSE: Unknown anchor type returns failure."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        entry = {
            "anchor_type": "blockchain_of_the_future",
            "chain_head_hash": "a" * 64,
        }
        ok, detail = verify_anchor(entry, deck_dir)
        assert ok is False
        assert "Unknown" in detail


# ---------------------------------------------------------------------------
# Tamper after anchoring
# ---------------------------------------------------------------------------

class TestTamperAfterAnchoring:
    """Tests that tampering AFTER anchoring is detected when the
    anchor is checked."""

    def test_tampered_chain_head_doesnt_match_anchor(self, tmp_path):
        """DEFENSE: If chain head changes after anchoring, anchor check fails."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        chain = Chain()
        chain.append_turn(prompt="real", response="content")
        original_head = chain.head_hash

        # Anchor original
        result = sign_local(original_head, deck_dir)
        assert result.success

        # Tamper: add another turn (changes head hash)
        chain.append_turn(prompt="extra", response="turn")
        new_head = chain.head_hash
        assert new_head != original_head

        # Anchor still references original head
        ok, _ = verify_from_log(new_head, result.log_index, deck_dir)
        assert ok is False, "Tampered chain doesn't match original anchor"

        # But original hash still verifies
        ok_orig, _ = verify_from_log(original_head, result.log_index, deck_dir)
        assert ok_orig is True

    def test_proof_bundle_with_anchor_detects_chain_modification(self, tmp_path):
        """DEFENSE: Proof bundle anchor catches modified chain head."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        chain = Chain()
        chain.append_turn(prompt="original", response="content")

        result = sign_local(chain.head_hash, deck_dir)
        anchor_ref = AnchorRef(
            anchor_type="local",
            chain_head_hash=chain.head_hash,
            reference=f"local:log_index={result.log_index}",
            timestamp=result.timestamp,
        )

        # Create bundle with anchor pointing to original head
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[],
            anchors=[anchor_ref],
        )

        # Bundle verifies
        vr = verify_proof_bundle(bundle)
        assert vr.is_valid is True

        # Now "tamper" the chain in the bundle
        chain.append_turn(prompt="extra", response="turn")
        tampered_bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[],
            anchors=[anchor_ref],  # Anchor still references OLD head
        )

        vr2 = verify_proof_bundle(tampered_bundle)
        assert vr2.is_valid is False, "Anchor hash doesn't match new chain head"


# ---------------------------------------------------------------------------
# Key file permissions
# ---------------------------------------------------------------------------

class TestKeyFilePermissions:

    def test_key_file_created_with_restricted_permissions(self, tmp_path):
        """Key file should be owner-only read/write (0o600)."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        _load_or_create_key(deck_dir)

        key_file = _key_path(deck_dir)
        mode = key_file.stat().st_mode & 0o777
        assert mode == 0o600, f"Key file permissions are {oct(mode)}, expected 0o600"

    def test_key_is_32_bytes(self, tmp_path):
        """Key should be exactly 32 bytes (256 bits)."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        key, _ = _load_or_create_key(deck_dir)
        assert len(key) == 32

    def test_key_persists_across_loads(self, tmp_path):
        """Same key returned on subsequent loads."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        key1, kid1 = _load_or_create_key(deck_dir)
        key2, kid2 = _load_or_create_key(deck_dir)

        assert key1 == key2
        assert kid1 == kid2
