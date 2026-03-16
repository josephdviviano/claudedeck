"""Tests for claudedeck.anchoring — unified anchor orchestrator."""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from claudedeck.core import Chain
from claudedeck.anchoring import (
    anchor,
    anchor_all,
    read_log_entries,
    verify_anchor,
    _log_path,
    _write_log_entry,
    AnchorResult,
    BACKENDS,
)
from claudedeck.signing import validate_hash_only


VALID_HASH = "a" * 64


# ---------------------------------------------------------------------------
# Orchestrator dispatch
# ---------------------------------------------------------------------------

class TestAnchorDispatch:
    def test_local_backend(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        result = anchor(VALID_HASH, "local", deck)
        assert result.success is True
        assert result.anchor_type == "local"
        assert result.chain_head_hash == VALID_HASH
        assert "local:" in result.reference
        assert result.extra["signature"]
        assert result.extra["key_id"]

    def test_sigstore_backend_not_installed(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        with patch("claudedeck.signing.shutil.which", return_value=None):
            result = anchor(VALID_HASH, "sigstore", deck)
        assert result.success is False
        assert "cosign not found" in result.error

    def test_ots_backend_not_installed(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        with patch("claudedeck.signing.shutil.which", return_value=None):
            result = anchor(VALID_HASH, "ots", deck)
        assert result.success is False
        assert "ots not found" in result.error

    def test_unknown_backend(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        result = anchor(VALID_HASH, "unknown", deck)
        assert result.success is False
        assert "Unknown backend" in result.error

    def test_plaintext_rejected(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        with pytest.raises(ValueError, match="not a valid SHA-256"):
            anchor("this is plaintext not a hash", "local", deck)

    def test_sigstore_success_mocked(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.rekor_log_index = "12345"
        mock_result.rekor_url = "https://search.sigstore.dev/?logIndex=12345"

        with patch("claudedeck.signing.sign_with_sigstore", return_value=mock_result):
            result = anchor(VALID_HASH, "sigstore", deck)

        assert result.success is True
        assert result.anchor_type == "sigstore"
        assert "rekor:12345" in result.reference
        assert result.extra["rekor_log_index"] == "12345"

    def test_ots_success_mocked(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.proof_path = str(deck / "abc.sha256.ots")

        with patch("claudedeck.signing.stamp_with_ots", return_value=mock_result):
            result = anchor(VALID_HASH, "ots", deck)

        assert result.success is True
        assert result.anchor_type == "ots"
        assert "ots:" in result.reference
        assert result.extra["ots_proof_path"]


class TestAnchorAll:
    def test_all_local_only(self, tmp_path):
        """With only local available, sigstore/ots should fail gracefully."""
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        with patch("claudedeck.signing.shutil.which", return_value=None):
            results = anchor_all(VALID_HASH, list(BACKENDS), deck)

        assert len(results) == 3
        local_result = next(r for r in results if r.anchor_type == "local")
        assert local_result.success is True

        sigstore_result = next(r for r in results if r.anchor_type == "sigstore")
        assert sigstore_result.success is False

        ots_result = next(r for r in results if r.anchor_type == "ots")
        assert ots_result.success is False

    def test_partial_failure_doesnt_block(self, tmp_path):
        """Failure on one backend shouldn't prevent others from running."""
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        results = anchor_all(VALID_HASH, ["local", "local"], deck)
        assert all(r.success for r in results)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Unified anchor log
# ---------------------------------------------------------------------------

class TestAnchorLog:
    def test_local_writes_to_log(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        anchor(VALID_HASH, "local", deck)
        entries = read_log_entries(deck)
        assert len(entries) == 1
        assert entries[0]["chain_head_hash"] == VALID_HASH

    def test_sigstore_writes_to_log(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.rekor_log_index = "99"
        mock_result.rekor_url = "https://search.sigstore.dev/?logIndex=99"

        with patch("claudedeck.signing.sign_with_sigstore", return_value=mock_result):
            anchor(VALID_HASH, "sigstore", deck)

        entries = read_log_entries(deck)
        assert any(e["anchor_type"] == "sigstore" for e in entries)

    def test_filter_by_hash(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        hash2 = "b" * 64
        anchor(VALID_HASH, "local", deck)
        anchor(hash2, "local", deck)

        entries = read_log_entries(deck, chain_head_hash=VALID_HASH)
        assert len(entries) == 1
        assert entries[0]["chain_head_hash"] == VALID_HASH

    def test_backward_compat_old_entries(self, tmp_path):
        """Old log entries without anchor_type should be treated as local."""
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        log = _log_path(deck)
        old_entry = {
            "index": 0,
            "chain_head_hash": VALID_HASH,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "signature": "abc123",
            "key_id": "def456",
        }
        with open(log, "w") as f:
            f.write(json.dumps(old_entry) + "\n")

        entries = read_log_entries(deck)
        assert entries[0]["anchor_type"] == "local"
        assert entries[0]["extra"] == {}

    def test_log_indices_increment(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        anchor(VALID_HASH, "local", deck)
        anchor(VALID_HASH, "local", deck)
        entries = read_log_entries(deck)
        indices = [e["index"] for e in entries]
        assert indices == [0, 1]


# ---------------------------------------------------------------------------
# Verification dispatch
# ---------------------------------------------------------------------------

class TestVerifyAnchor:
    def test_verify_local(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        anchor(VALID_HASH, "local", deck)

        entries = read_log_entries(deck)
        ok, detail = verify_anchor(entries[0], deck)
        assert ok is True
        assert "valid" in detail.lower()

    def test_verify_local_tampered_signature(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        anchor(VALID_HASH, "local", deck)

        entries = read_log_entries(deck)
        entries[0]["extra"]["signature"] = "tampered" + "0" * 56
        ok, detail = verify_anchor(entries[0], deck)
        assert ok is False

    def test_verify_sigstore_no_cosign(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        entry = {
            "anchor_type": "sigstore",
            "chain_head_hash": VALID_HASH,
            "extra": {"rekor_log_index": "12345"},
        }
        with patch("claudedeck.signing.shutil.which", return_value=None):
            ok, detail = verify_anchor(entry, deck)
        assert ok is False
        assert "cosign not available" in detail or "not found" in detail.lower()

    def test_verify_ots_no_ots_cli(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        entry = {
            "anchor_type": "ots",
            "chain_head_hash": VALID_HASH,
            "extra": {"ots_proof_path": "/tmp/fake.ots"},
        }
        with patch("claudedeck.signing.shutil.which", return_value=None):
            ok, detail = verify_anchor(entry, deck)
        assert ok is False
        assert "ots not available" in detail or "not found" in detail.lower()

    def test_verify_unknown_type(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        entry = {
            "anchor_type": "blockchain3000",
            "chain_head_hash": VALID_HASH,
        }
        ok, detail = verify_anchor(entry, deck)
        assert ok is False
        assert "Unknown" in detail

    def test_verify_missing_signature(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()
        entry = {
            "anchor_type": "local",
            "chain_head_hash": VALID_HASH,
            "extra": {},
        }
        ok, detail = verify_anchor(entry, deck)
        assert ok is False


# ---------------------------------------------------------------------------
# End-to-end: chain → anchor → verify
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_chain_anchor_verify_local(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()

        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.append_turn(prompt="foo", response="bar")
        chain.save(deck / "test.chain.jsonl")

        result = anchor(chain.head_hash, "local", deck)
        assert result.success is True

        entries = read_log_entries(deck, chain.head_hash)
        ok, detail = verify_anchor(entries[0], deck)
        assert ok is True

    def test_anchor_then_tamper_fails(self, tmp_path):
        deck = tmp_path / ".claudedeck"
        deck.mkdir()

        chain = Chain()
        chain.append_turn(prompt="hello", response="world")

        result = anchor(chain.head_hash, "local", deck)
        assert result.success is True

        # Tamper with the log entry's hash
        entries = read_log_entries(deck)
        entries[0]["chain_head_hash"] = "f" * 64
        ok, detail = verify_anchor(entries[0], deck)
        assert ok is False


# ---------------------------------------------------------------------------
# Proof bundle with anchors
# ---------------------------------------------------------------------------

class TestProofBundleAnchors:
    def test_bundle_with_local_anchor(self, tmp_path):
        from claudedeck.proof import ProofBundle, AnchorRef, verify_proof_bundle, DisclosedTurn

        chain = Chain()
        chain.append_turn(prompt="hi", response="hey")

        anchor_ref = AnchorRef(
            anchor_type="local",
            chain_head_hash=chain.head_hash,
            reference="local:log_index=0,key_id=abc",
            timestamp="2026-03-16T00:00:00Z",
        )
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(seq=0, prompt="hi", response="hey", artifacts={})],
            anchors=[anchor_ref],
        )
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True

    def test_bundle_with_sigstore_anchor(self, tmp_path):
        from claudedeck.proof import ProofBundle, AnchorRef, verify_proof_bundle, DisclosedTurn

        chain = Chain()
        chain.append_turn(prompt="hi", response="hey")

        anchor_ref = AnchorRef(
            anchor_type="sigstore",
            chain_head_hash=chain.head_hash,
            reference="rekor:12345",
            timestamp="2026-03-16T00:00:00Z",
        )
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(seq=0, prompt="hi", response="hey", artifacts={})],
            anchors=[anchor_ref],
        )
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True

    def test_bundle_with_ots_anchor_and_proof_data(self, tmp_path):
        from claudedeck.proof import ProofBundle, AnchorRef, verify_proof_bundle, DisclosedTurn
        import base64

        chain = Chain()
        chain.append_turn(prompt="hi", response="hey")

        fake_proof = base64.b64encode(b"fake ots proof bytes").decode("ascii")
        anchor_ref = AnchorRef(
            anchor_type="ots",
            chain_head_hash=chain.head_hash,
            reference="ots:/tmp/proof.ots",
            timestamp="2026-03-16T00:00:00Z",
            proof_data=fake_proof,
        )
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(seq=0, prompt="hi", response="hey", artifacts={})],
            anchors=[anchor_ref],
        )

        # Save and reload to test proof_data roundtrip
        path = tmp_path / "bundle.json"
        bundle.save(path)
        loaded = ProofBundle.load(path)

        assert loaded.anchors[0].proof_data == fake_proof
        result = verify_proof_bundle(loaded)
        assert result.is_valid is True

    def test_bundle_multiple_anchor_types(self):
        from claudedeck.proof import ProofBundle, AnchorRef, verify_proof_bundle, DisclosedTurn

        chain = Chain()
        chain.append_turn(prompt="hi", response="hey")

        anchors = [
            AnchorRef(anchor_type="local", chain_head_hash=chain.head_hash, reference="local:0"),
            AnchorRef(anchor_type="sigstore", chain_head_hash=chain.head_hash, reference="rekor:99"),
            AnchorRef(anchor_type="ots", chain_head_hash=chain.head_hash, reference="ots:proof.ots"),
        ]
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(seq=0, prompt="hi", response="hey", artifacts={})],
            anchors=anchors,
        )
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True
        anchor_checks = [c for c in result.checks if c["check"].startswith("anchor_") and c["check"] != "anchor_note"]
        assert len(anchor_checks) == 3
