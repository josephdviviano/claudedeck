"""Tests for claudedeck.local_anchor — local signing backend for testing."""

import json
import pytest

from claudedeck.core import Chain, sha256_hex
from claudedeck.local_anchor import (
    sign_local,
    verify_local,
    verify_from_log,
    _load_or_create_key,
    _key_path,
    _log_path,
)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

class TestKeyManagement:
    def test_auto_creates_key(self, tmp_path):
        key, key_id = _load_or_create_key(tmp_path)
        assert len(key) == 32
        assert len(key_id) == 64
        assert _key_path(tmp_path).exists()

    def test_key_persists(self, tmp_path):
        key1, id1 = _load_or_create_key(tmp_path)
        key2, id2 = _load_or_create_key(tmp_path)
        assert key1 == key2
        assert id1 == id2

    def test_key_permissions(self, tmp_path):
        _load_or_create_key(tmp_path)
        mode = _key_path(tmp_path).stat().st_mode & 0o777
        assert mode == 0o600

    def test_different_dirs_get_different_keys(self, tmp_path):
        dir1 = tmp_path / "a"
        dir2 = tmp_path / "b"
        _, id1 = _load_or_create_key(dir1)
        _, id2 = _load_or_create_key(dir2)
        assert id1 != id2


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

class TestSignLocal:
    def test_sign_returns_success(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)
        assert result.success is True
        assert result.signature is not None
        assert len(result.signature) == 64
        assert result.key_id is not None
        assert result.timestamp is not None
        assert result.log_index == 0

    def test_sign_increments_log_index(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        r1 = sign_local(chain.head_hash, tmp_path)
        r2 = sign_local(chain.head_hash, tmp_path)
        assert r1.log_index == 0
        assert r2.log_index == 1

    def test_sign_writes_log(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        sign_local(chain.head_hash, tmp_path)

        log = _log_path(tmp_path)
        assert log.exists()
        entry = json.loads(log.read_text().strip())
        assert entry["chain_head_hash"] == chain.head_hash
        assert "signature" in entry
        assert "timestamp" in entry

    def test_sign_rejects_plaintext(self, tmp_path):
        with pytest.raises(ValueError):
            sign_local("this is plaintext not a hash", tmp_path)

    def test_different_hashes_get_different_signatures(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        r1 = sign_local(chain.head_hash, tmp_path)

        chain2 = Chain()
        chain2.append_turn(prompt="different", response="content")
        r2 = sign_local(chain2.head_hash, tmp_path)

        assert r1.signature != r2.signature


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class TestVerifyLocal:
    def test_verify_valid_signature(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        ok, detail = verify_local(
            chain.head_hash, result.signature, result.timestamp, tmp_path,
        )
        assert ok is True
        assert "valid" in detail.lower()

    def test_verify_tampered_hash(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        # Try to verify with a different hash
        fake_hash = sha256_hex(b"tampered")
        ok, detail = verify_local(
            fake_hash, result.signature, result.timestamp, tmp_path,
        )
        assert ok is False
        assert "INVALID" in detail

    def test_verify_tampered_timestamp(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        ok, detail = verify_local(
            chain.head_hash, result.signature, "2000-01-01T00:00:00+00:00", tmp_path,
        )
        assert ok is False

    def test_verify_tampered_signature(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        ok, detail = verify_local(
            chain.head_hash, "f" * 64, result.timestamp, tmp_path,
        )
        assert ok is False

    def test_verify_missing_key(self, tmp_path):
        ok, detail = verify_local("a" * 64, "b" * 64, "2026-01-01T00:00:00+00:00", tmp_path)
        assert ok is False
        assert "not found" in detail.lower()

    def test_verify_wrong_key(self, tmp_path):
        """Signing with one key and verifying with another should fail."""
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")

        dir1 = tmp_path / "signer"
        dir2 = tmp_path / "verifier"
        result = sign_local(chain.head_hash, dir1)

        # Create a different key in dir2
        _load_or_create_key(dir2)

        ok, detail = verify_local(
            chain.head_hash, result.signature, result.timestamp, dir2,
        )
        assert ok is False


# ---------------------------------------------------------------------------
# Log verification
# ---------------------------------------------------------------------------

class TestVerifyFromLog:
    def test_verify_from_log(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        ok, detail = verify_from_log(chain.head_hash, result.log_index, tmp_path)
        assert ok is True

    def test_verify_from_log_wrong_hash(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        ok, detail = verify_from_log(sha256_hex(b"wrong"), result.log_index, tmp_path)
        assert ok is False
        assert "mismatch" in detail.lower()

    def test_verify_from_log_bad_index(self, tmp_path):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        sign_local(chain.head_hash, tmp_path)

        ok, detail = verify_from_log(chain.head_hash, 999, tmp_path)
        assert ok is False

    def test_verify_from_log_missing(self, tmp_path):
        ok, detail = verify_from_log("a" * 64, 0, tmp_path)
        assert ok is False
        assert "not found" in detail.lower()

    def test_multiple_anchors_same_hash(self, tmp_path):
        """Multiple anchors for the same hash should all verify."""
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")

        r1 = sign_local(chain.head_hash, tmp_path)
        r2 = sign_local(chain.head_hash, tmp_path)

        ok1, _ = verify_from_log(chain.head_hash, r1.log_index, tmp_path)
        ok2, _ = verify_from_log(chain.head_hash, r2.log_index, tmp_path)
        assert ok1 is True
        assert ok2 is True


# ---------------------------------------------------------------------------
# End-to-end: chain → anchor → proof → verify
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_full_flow(self, tmp_path):
        """Complete flow: build chain, anchor locally, create proof bundle, verify."""
        from claudedeck.proof import ProofBundle, DisclosedTurn, AnchorRef, verify_proof_bundle

        # Build chain
        chain = Chain()
        chain.append_turn(prompt="Write a test", response="Here's your test code.")
        chain.append_turn(prompt="Add edge cases", response="Added null and empty checks.")

        # Anchor locally
        result = sign_local(chain.head_hash, tmp_path)
        assert result.success

        # Create proof bundle with local anchor
        anchor = AnchorRef(
            anchor_type="local",
            chain_head_hash=chain.head_hash,
            reference=f"local:log_index={result.log_index},key_id={result.key_id[:16]},sig={result.signature[:16]}",
            timestamp=result.timestamp,
        )

        bundle = ProofBundle(
            chain_records=[rec.to_dict() for rec in chain.records],
            disclosed_turns=[
                DisclosedTurn(seq=0, prompt="Write a test", response="Here's your test code.", artifacts={}),
                DisclosedTurn(seq=1, prompt="Add edge cases", response="Added null and empty checks.", artifacts={}),
            ],
            anchors=[anchor],
        )

        # Verify proof bundle (chain + content + anchor ref)
        vresult = verify_proof_bundle(bundle)
        assert vresult.is_valid is True

        # Verify local anchor independently
        ok, detail = verify_from_log(chain.head_hash, result.log_index, tmp_path)
        assert ok is True

    def test_tampered_chain_fails_anchor(self, tmp_path):
        """If the chain is tampered after anchoring, anchor verification should fail."""
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        result = sign_local(chain.head_hash, tmp_path)

        # "Tamper" by building a different chain
        chain2 = Chain()
        chain2.append_turn(prompt="hello", response="TAMPERED world")

        # The anchor was for the original chain head
        ok, _ = verify_from_log(chain2.head_hash, result.log_index, tmp_path)
        assert ok is False

    def test_anchor_log_is_append_only(self, tmp_path):
        """Verify that the log grows monotonically."""
        chain = Chain()
        chain.append_turn(prompt="a", response="b")

        for i in range(5):
            r = sign_local(chain.head_hash, tmp_path)
            assert r.log_index == i

        log = _log_path(tmp_path)
        with open(log) as f:
            entries = [json.loads(line) for line in f]
        assert len(entries) == 5
        assert [e["index"] for e in entries] == [0, 1, 2, 3, 4]
