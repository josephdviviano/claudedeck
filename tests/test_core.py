"""Tests for claudedeck.core — chain integrity and tamper detection."""

import copy
import json
import pytest

from claudedeck.core import (
    Chain, ChainRecord, TurnData, ArtifactRef,
    sha256_hex, canonical_json, generate_nonce, GENESIS_HASH,
)


# ---------------------------------------------------------------------------
# Basic chain operations
# ---------------------------------------------------------------------------

class TestChainAppend:
    def test_append_creates_record(self):
        chain = Chain()
        rec = chain.append_turn(prompt="hello", response="world")
        assert rec.seq == 0
        assert rec.prev_hash == GENESIS_HASH
        assert len(rec.record_hash) == 64
        assert len(chain.records) == 1

    def test_chain_linkage(self, chain_3turns):
        recs = chain_3turns.records
        assert recs[0].prev_hash == GENESIS_HASH
        assert recs[1].prev_hash == recs[0].record_hash
        assert recs[2].prev_hash == recs[1].record_hash

    def test_seq_monotonic(self, chain_3turns):
        for i, rec in enumerate(chain_3turns.records):
            assert rec.seq == i

    def test_head_hash_tracks_last(self, chain_3turns):
        assert chain_3turns.head_hash == chain_3turns.records[-1].record_hash

    def test_head_hash_empty_is_genesis(self):
        assert Chain().head_hash == GENESIS_HASH

    def test_nonce_uniqueness(self):
        chain = Chain()
        r0 = chain.append_turn(prompt="a", response="b")
        r1 = chain.append_turn(prompt="c", response="d")
        assert r0.nonce != r1.nonce

    def test_verify_valid_chain(self, chain_3turns):
        valid, errors = chain_3turns.verify()
        assert valid is True
        assert errors == []


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_tamper_record_hash(self, chain_3turns):
        chain_3turns.records[1].record_hash = "a" * 64
        valid, errors = chain_3turns.verify()
        assert valid is False
        assert any("record_hash mismatch" in e for e in errors)

    def test_tamper_prev_hash(self, chain_3turns):
        chain_3turns.records[2].prev_hash = "b" * 64
        valid, errors = chain_3turns.verify()
        assert valid is False
        assert any("prev_hash" in e for e in errors)

    def test_tamper_prompt_hash(self, chain_3turns):
        """Modifying the prompt hash changes the computed record hash."""
        rec = chain_3turns.records[1]
        original_hash = rec.record_hash
        rec.turn.prompt_hash = sha256_hex(b"tampered prompt")
        assert rec.compute_hash() != original_hash

    def test_tamper_response_hash(self, chain_3turns):
        rec = chain_3turns.records[1]
        original_hash = rec.record_hash
        rec.turn.response_hash = sha256_hex(b"tampered response")
        assert rec.compute_hash() != original_hash

    def test_swap_prompt_response(self, chain_3turns):
        """Swapping prompt and response hashes changes the record hash."""
        rec = chain_3turns.records[0]
        original = rec.record_hash
        rec.turn.prompt_hash, rec.turn.response_hash = rec.turn.response_hash, rec.turn.prompt_hash
        assert rec.compute_hash() != original

    def test_insert_record(self, chain_3turns):
        """Inserting a fake record breaks the chain."""
        fake = ChainRecord(
            seq=1,
            nonce=generate_nonce(),
            turn=TurnData.from_plaintext("fake", "record"),
            timestamp="2026-01-01T00:00:00+00:00",
            prev_hash=chain_3turns.records[0].record_hash,
        ).finalize()
        chain_3turns.records.insert(1, fake)
        valid, errors = chain_3turns.verify()
        assert valid is False

    def test_delete_record(self, chain_3turns):
        """Removing a record from the middle breaks linkage."""
        del chain_3turns.records[1]
        valid, errors = chain_3turns.verify()
        assert valid is False

    def test_reorder_records(self, chain_3turns):
        """Swapping two records breaks both seq and linkage."""
        chain_3turns.records[0], chain_3turns.records[1] = (
            chain_3turns.records[1], chain_3turns.records[0]
        )
        valid, errors = chain_3turns.verify()
        assert valid is False

    def test_tamper_nonce(self, chain_3turns):
        """Changing the nonce changes the computed hash."""
        rec = chain_3turns.records[0]
        original = rec.record_hash
        rec.nonce = generate_nonce()
        assert rec.compute_hash() != original

    def test_tamper_timestamp(self, chain_3turns):
        """Changing the timestamp changes the computed hash."""
        rec = chain_3turns.records[0]
        original = rec.record_hash
        rec.timestamp = "2000-01-01T00:00:00+00:00"
        assert rec.compute_hash() != original


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_save_load_roundtrip(self, chain_3turns, tmp_path):
        path = tmp_path / "chain.jsonl"
        chain_3turns.save(path)
        loaded = Chain.load(path)

        assert len(loaded.records) == len(chain_3turns.records)
        for orig, loaded_rec in zip(chain_3turns.records, loaded.records):
            assert loaded_rec.record_hash == orig.record_hash
            assert loaded_rec.prev_hash == orig.prev_hash
            assert loaded_rec.seq == orig.seq
            assert loaded_rec.nonce == orig.nonce
            assert loaded_rec.turn.prompt_hash == orig.turn.prompt_hash
            assert loaded_rec.turn.response_hash == orig.turn.response_hash

        # Loaded chain should also verify
        valid, errors = loaded.verify()
        assert valid is True

    def test_canonical_json_deterministic(self):
        d1 = {"z": 1, "a": 2, "m": 3}
        d2 = {"a": 2, "m": 3, "z": 1}
        assert canonical_json(d1) == canonical_json(d2)

    def test_canonical_json_no_whitespace(self):
        result = canonical_json({"key": "value"})
        assert b" " not in result
        assert b"\n" not in result

    def test_canonical_json_ascii(self):
        result = canonical_json({"emoji": "\U0001f600"})
        assert b"\\u" in result  # non-ASCII should be escaped


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

class TestArtifacts:
    def test_artifact_from_file(self, tmp_path):
        f = tmp_path / "script.py"
        f.write_text("print('hello')")
        ref = ArtifactRef.from_file(f)
        assert ref.filename == "script.py"
        assert len(ref.sha256) == 64
        assert ref.size_bytes == len("print('hello')")

    def test_artifact_roundtrip(self):
        ref = ArtifactRef(filename="test.py", sha256="a" * 64, size_bytes=42)
        d = ref.to_dict()
        restored = ArtifactRef.from_dict(d)
        assert restored.filename == ref.filename
        assert restored.sha256 == ref.sha256
        assert restored.size_bytes == ref.size_bytes

    def test_turn_with_artifact(self, tmp_path):
        f = tmp_path / "output.csv"
        f.write_text("x,y\n1,2\n")
        chain = Chain()
        rec = chain.append_turn(
            prompt="generate data",
            response="here's the csv",
            artifact_paths=[f],
        )
        assert len(rec.turn.artifacts) == 1
        assert rec.turn.artifacts[0].filename == "output.csv"
