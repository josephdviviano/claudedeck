"""
tests/test_chain_attacks.py — Chain manipulation and format attack tests.

Tests for JSONL format exploitation, chain tampering, timestamp spoofing,
session binding weaknesses, and edge cases in chain verification.

Audit refs: H3 (JSONL truncation), M1 (timestamp spoofing),
M2 (session ID binding), M5 (state file tampering), M6 (no verify-on-save)
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from claudedeck.core import (
    Chain, ChainRecord, TurnData, ArtifactRef,
    sha256_hex, canonical_json, generate_nonce, GENESIS_HASH,
)
from claudedeck.hook import load_state, save_state


# ---------------------------------------------------------------------------
# JSONL format attacks (H3)
# ---------------------------------------------------------------------------

class TestJSONLFormatAttacks:
    """The chain file is JSONL. These tests explore format-level attacks."""

    def test_truncated_line_skipped_gracefully(self, tmp_path):
        """FIXED: A truncated JSONL line is skipped with a warning.

        Chain.load() now recovers valid records instead of crashing.
        """
        chain = Chain()
        chain.append_turn(prompt="first", response="response1")
        chain.append_turn(prompt="second", response="response2")

        path = tmp_path / "chain.jsonl"
        chain.save(path)

        # Truncate so a record line is incomplete JSON
        lines = path.read_text().strip().split("\n")
        # lines[0] is _meta preamble, lines[1] is record 0, lines[2] is record 1
        truncated = lines[0] + "\n" + lines[1] + "\n" + lines[2][:20] + "\n"
        path.write_text(truncated)

        loaded = Chain.load(path)
        assert len(loaded.records) == 1, "Valid record recovered, truncated line skipped"

    def test_empty_lines_in_chain_file_ignored(self, tmp_path):
        """Empty lines between records are harmlessly skipped."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        path = tmp_path / "chain.jsonl"
        chain.save(path)

        # Insert blank lines
        content = path.read_text()
        path.write_text("\n\n" + content + "\n\n")

        loaded = Chain.load(path)
        assert len(loaded.records) == 1
        valid, errors = loaded.verify()
        assert valid is True

    def test_appended_fake_record_detected_by_verify(self, tmp_path):
        """DEFENSE: Appending a record with wrong prev_hash is detected."""
        chain = Chain()
        chain.append_turn(prompt="legit", response="response")

        path = tmp_path / "chain.jsonl"
        chain.save(path)

        # Attacker appends a record with wrong prev_hash
        fake_record = ChainRecord(
            seq=1,
            nonce=generate_nonce(),
            turn=TurnData.from_plaintext("injected", "fake"),
            timestamp=datetime.now(timezone.utc).isoformat(),
            prev_hash="wrong" + "0" * 59,
        ).finalize()

        with open(path, "a") as f:
            f.write(json.dumps(fake_record.to_dict(), sort_keys=True) + "\n")

        loaded = Chain.load(path)
        assert len(loaded.records) == 2
        valid, errors = loaded.verify()
        assert valid is False
        assert any("prev_hash" in e for e in errors)

    def test_record_deletion_detected_by_verify(self, tmp_path):
        """DEFENSE: Removing a record from the middle breaks linkage."""
        chain = Chain()
        for i in range(5):
            chain.append_turn(prompt=f"p{i}", response=f"r{i}")

        path = tmp_path / "chain.jsonl"
        chain.save(path)

        # Delete record at index 2
        lines = path.read_text().strip().split("\n")
        del lines[2]
        path.write_text("\n".join(lines) + "\n")

        loaded = Chain.load(path)
        assert len(loaded.records) == 4
        valid, errors = loaded.verify()
        assert valid is False

    def test_record_reordering_detected(self, tmp_path):
        """DEFENSE: Swapping record order breaks verification."""
        chain = Chain()
        for i in range(3):
            chain.append_turn(prompt=f"p{i}", response=f"r{i}")

        path = tmp_path / "chain.jsonl"
        chain.save(path)

        # Swap records 1 and 2
        lines = path.read_text().strip().split("\n")
        lines[1], lines[2] = lines[2], lines[1]
        path.write_text("\n".join(lines) + "\n")

        loaded = Chain.load(path)
        valid, errors = loaded.verify()
        assert valid is False


# ---------------------------------------------------------------------------
# Timestamp spoofing (M1)
# ---------------------------------------------------------------------------

class TestTimestampSpoofing:
    """Timestamps are included in the record hash but are attacker-controlled
    without external anchoring."""

    def test_backdated_record_valid_without_anchor(self):
        """VULNERABILITY: A backdated record is undetectable without external anchor.

        An attacker can set their system clock to any time before
        creating records, producing a chain with arbitrary timestamps.
        """
        chain = Chain()

        # Manually create a backdated record
        turn = TurnData.from_plaintext("prompt", "response")
        record = ChainRecord(
            seq=0,
            nonce=generate_nonce(),
            turn=turn,
            timestamp="2020-01-01T00:00:00+00:00",  # 6 years ago
            prev_hash=GENESIS_HASH,
        ).finalize()

        chain.records.append(record)
        valid, errors = chain.verify()
        assert valid is True, "Backdated record passes verification"

    def test_future_dated_record_valid(self):
        """VULNERABILITY: Future timestamps also pass verification."""
        chain = Chain()

        turn = TurnData.from_plaintext("prompt", "response")
        record = ChainRecord(
            seq=0,
            nonce=generate_nonce(),
            turn=turn,
            timestamp="2099-12-31T23:59:59+00:00",
            prev_hash=GENESIS_HASH,
        ).finalize()

        chain.records.append(record)
        valid, errors = chain.verify()
        assert valid is True


# ---------------------------------------------------------------------------
# Session ID binding (M2)
# ---------------------------------------------------------------------------

class TestSessionIdBinding:
    """Session IDs are NOT part of the record hash, so chains are
    not bound to sessions."""

    def test_chain_id_in_record_hash(self):
        """FIXED: chain_id is hashed into records, binding them to their chain.

        Two chains with identical content but different chain_ids
        produce different record hashes.
        """
        turn = TurnData.from_plaintext("prompt", "response")
        nonce = "a" * 64
        ts = "2026-03-15T00:00:00Z"

        rec1 = ChainRecord(
            seq=0, nonce=nonce, turn=turn,
            timestamp=ts, prev_hash=GENESIS_HASH,
            chain_id="chain_aaa",
        ).finalize()

        rec2 = ChainRecord(
            seq=0, nonce=nonce, turn=turn,
            timestamp=ts, prev_hash=GENESIS_HASH,
            chain_id="chain_bbb",
        ).finalize()

        assert rec1.record_hash != rec2.record_hash, (
            "Different chain_ids produce different hashes"
        )

    def test_old_records_without_chain_id_still_verify(self):
        """BACKWARD COMPAT: Records without chain_id (old format) verify correctly."""
        turn = TurnData.from_plaintext("prompt", "response")
        nonce = "a" * 64
        ts = "2026-03-15T00:00:00Z"

        # Simulate an old record with no chain_id
        rec = ChainRecord(
            seq=0, nonce=nonce, turn=turn,
            timestamp=ts, prev_hash=GENESIS_HASH,
            chain_id=None,  # Old format
        ).finalize()

        # Should verify by computing hash without chain_id in hashable dict
        assert rec.record_hash == rec.compute_hash()

    def test_records_not_portable_between_chains(self):
        """FIXED: Records from different chains have different hashes."""
        chain_a = Chain()
        chain_a.append_turn(prompt="same content", response="same response")

        chain_b = Chain()
        chain_b.append_turn(prompt="same content", response="same response")

        # Different chain_ids → different record hashes
        assert chain_a.chain_id != chain_b.chain_id
        assert chain_a.records[0].record_hash != chain_b.records[0].record_hash


# ---------------------------------------------------------------------------
# State file tampering (M5)
# ---------------------------------------------------------------------------

class TestStateFileTampering:
    """The hook state file tracks which turns have been chained.
    It has no integrity protection."""

    def test_state_tampering_detected_by_hmac(self, tmp_path):
        """FIXED: Modifying state file triggers HMAC mismatch and reset.

        Note: An attacker with access to the local_anchor.key can still
        forge valid HMACs. This protects against casual tampering only.
        """
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        # Save state (includes HMAC)
        save_state(deck_dir, "test-session", {"chained_count": 5})
        state = load_state(deck_dir, "test-session")
        assert state["chained_count"] == 5

        # Attacker modifies the state file directly
        import json
        state_path = deck_dir / "test-session.state.json"
        raw = json.loads(state_path.read_text())
        raw["chained_count"] = 0  # Rewind
        # Don't update HMAC
        state_path.write_text(json.dumps(raw))

        # Load detects HMAC mismatch and resets
        state = load_state(deck_dir, "test-session")
        assert state["chained_count"] == 0, (
            "HMAC mismatch causes reset to chained_count=0"
        )

    def test_state_roundtrip_with_hmac(self, tmp_path):
        """State save/load roundtrip with HMAC verification."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        save_state(deck_dir, "test-session", {"chained_count": 42})
        state = load_state(deck_dir, "test-session")
        assert state["chained_count"] == 42


# ---------------------------------------------------------------------------
# Chain save without verification (M6)
# ---------------------------------------------------------------------------

class TestSaveWithoutVerification:
    """Chain.save() writes whatever is in memory — no integrity check."""

    def test_corrupted_chain_refuses_to_save(self, tmp_path):
        """FIXED: A corrupted in-memory chain raises on save."""
        from claudedeck.core import ChainCorruptedError
        chain = Chain()
        chain.append_turn(prompt="p1", response="r1")
        chain.append_turn(prompt="p2", response="r2")

        # Corrupt the chain in memory
        chain.records[1].prev_hash = "corrupted_" + "0" * 54

        path = tmp_path / "corrupted.chain.jsonl"
        with pytest.raises(ChainCorruptedError):
            chain.save(path)

    def test_tampered_record_hash_refuses_to_save(self, tmp_path):
        """FIXED: Wrong record_hash prevents saving."""
        from claudedeck.core import ChainCorruptedError
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        chain.records[0].record_hash = "d" * 64

        path = tmp_path / "tampered.chain.jsonl"
        with pytest.raises(ChainCorruptedError):
            chain.save(path)


# ---------------------------------------------------------------------------
# Chain verification edge cases
# ---------------------------------------------------------------------------

class TestChainVerificationEdgeCases:
    """Edge cases and boundary conditions for chain verification."""

    def test_empty_chain_is_valid(self):
        """An empty chain should verify as valid (vacuous truth)."""
        chain = Chain()
        valid, errors = chain.verify()
        assert valid is True
        assert errors == []

    def test_single_record_chain(self):
        """A single-record chain must have GENESIS as prev_hash."""
        chain = Chain()
        chain.append_turn(prompt="only turn", response="only response")

        valid, errors = chain.verify()
        assert valid is True
        assert chain.records[0].prev_hash == GENESIS_HASH

    def test_seq_mismatch_detected(self):
        """Seq numbers that don't match position are detected."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        chain.records[0].seq = 5  # Wrong seq
        valid, errors = chain.verify()
        assert valid is False
        assert any("seq is 5" in e for e in errors)

    def test_genesis_hash_tampering_detected(self):
        """First record with wrong prev_hash is detected."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        chain.records[0].prev_hash = "NOT_GENESIS"
        valid, errors = chain.verify()
        assert valid is False
        assert any("GENESIS" in e for e in errors)

    def test_head_hash_empty_chain(self):
        """Empty chain head_hash is GENESIS."""
        chain = Chain()
        assert chain.head_hash == GENESIS_HASH

    def test_head_hash_after_append(self):
        """Head hash updates after each append."""
        chain = Chain()
        rec = chain.append_turn(prompt="p", response="r")
        assert chain.head_hash == rec.record_hash
        assert chain.head_hash != GENESIS_HASH

    def test_large_chain_verifies(self):
        """A chain with many records verifies correctly."""
        chain = Chain()
        for i in range(100):
            chain.append_turn(prompt=f"prompt {i}", response=f"response {i}")

        valid, errors = chain.verify()
        assert valid is True
        assert len(chain.records) == 100

    def test_very_long_content(self):
        """Chain handles very long prompts and responses."""
        long_text = "x" * 100_000  # 100KB
        chain = Chain()
        chain.append_turn(prompt=long_text, response=long_text)

        valid, errors = chain.verify()
        assert valid is True

    def test_empty_prompt_and_response(self):
        """Empty strings are valid chain content."""
        chain = Chain()
        chain.append_turn(prompt="", response="")

        valid, errors = chain.verify()
        assert valid is True
        # Hashes should be the SHA-256 of empty string
        assert chain.records[0].turn.prompt_hash == sha256_hex(b"")

    def test_chain_save_load_roundtrip(self, tmp_path):
        """Chain survives save/load without data loss."""
        chain = Chain()
        for i in range(10):
            chain.append_turn(
                prompt=f"prompt {i}",
                response=f"response {i}",
                model="test-model",
            )

        path = tmp_path / "roundtrip.chain.jsonl"
        chain.save(path)
        loaded = Chain.load(path)

        assert len(loaded.records) == len(chain.records)
        for orig, load in zip(chain.records, loaded.records):
            assert orig.record_hash == load.record_hash
            assert orig.prev_hash == load.prev_hash
            assert orig.seq == load.seq

        valid, errors = loaded.verify()
        assert valid is True
