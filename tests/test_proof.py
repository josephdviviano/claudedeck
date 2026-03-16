"""Tests for claudedeck.proof — proof bundles, selective disclosure, tamper detection."""

import copy
import json
import pytest

from claudedeck.core import Chain, sha256_hex
from claudedeck.proof import (
    ProofBundle,
    DisclosedTurn,
    AnchorRef,
    verify_proof_bundle,
)
from tests.conftest import SAMPLE_TURNS


def _make_bundle(chain, vault_data, disclose_seqs=None, anchors=None):
    """Helper to create a ProofBundle from chain + vault dict."""
    if disclose_seqs is None:
        disclose_seqs = list(range(len(chain.records)))

    disclosed = []
    for seq in disclose_seqs:
        entry = vault_data[str(seq)]
        disclosed.append(DisclosedTurn(
            seq=seq,
            prompt=entry["prompt"],
            response=entry["response"],
            artifacts=entry.get("artifacts", {}),
        ))

    return ProofBundle(
        chain_records=[rec.to_dict() for rec in chain.records],
        disclosed_turns=disclosed,
        anchors=anchors or [],
    )


# ---------------------------------------------------------------------------
# Valid bundle verification
# ---------------------------------------------------------------------------

class TestValidBundle:
    def test_create_and_verify(self, chain_3turns, vault_data):
        bundle = _make_bundle(chain_3turns, vault_data)
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True
        assert all(c["passed"] for c in result.checks)

    def test_save_load_roundtrip(self, chain_3turns, vault_data, tmp_path):
        bundle = _make_bundle(chain_3turns, vault_data)
        path = tmp_path / "bundle.json"
        bundle.save(path)

        loaded = ProofBundle.load(path)
        result = verify_proof_bundle(loaded)
        assert result.is_valid is True

    def test_with_anchors(self, chain_3turns, vault_data):
        anchor = AnchorRef(
            anchor_type="sigstore",
            chain_head_hash=chain_3turns.head_hash,
            reference="rekor-12345",
            timestamp="2026-03-15T12:00:00Z",
        )
        bundle = _make_bundle(chain_3turns, vault_data, anchors=[anchor])
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# Selective disclosure
# ---------------------------------------------------------------------------

class TestSelectiveDisclosure:
    def test_partial_disclosure(self, chain_3turns, vault_data):
        """Disclosing only turns 0 and 2 should still verify."""
        bundle = _make_bundle(chain_3turns, vault_data, disclose_seqs=[0, 2])
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True

    def test_redacted_turns_still_in_chain(self, chain_3turns, vault_data):
        """All chain records present even when turns are redacted."""
        bundle = _make_bundle(chain_3turns, vault_data, disclose_seqs=[0])
        assert len(bundle.chain_records) == 3  # All records
        assert len(bundle.disclosed_turns) == 1  # Only turn 0

    def test_no_disclosure(self, chain_3turns, vault_data):
        """Bundle with zero disclosed turns — chain still verifies."""
        bundle = _make_bundle(chain_3turns, vault_data, disclose_seqs=[])
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True
        assert len(bundle.disclosed_turns) == 0

    def test_chain_integrity_across_redacted(self, chain_3turns, vault_data):
        """Chain linkage is verified across ALL records, not just disclosed ones."""
        bundle = _make_bundle(chain_3turns, vault_data, disclose_seqs=[2])
        # Verify that chain integrity check covers all 3 records
        result = verify_proof_bundle(bundle)
        chain_check = next(c for c in result.checks if c["check"] == "chain_integrity")
        assert "3 records" in chain_check["detail"]


# ---------------------------------------------------------------------------
# Tamper detection in bundles
# ---------------------------------------------------------------------------

class TestBundleTamperDetection:
    def test_tampered_prompt(self, chain_3turns, vault_data):
        bundle = _make_bundle(chain_3turns, vault_data)
        bundle.disclosed_turns[0].prompt = "I changed this prompt"
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False
        assert any("PROMPT HASH MISMATCH" in c["detail"] for c in result.checks)

    def test_tampered_response(self, chain_3turns, vault_data):
        bundle = _make_bundle(chain_3turns, vault_data)
        bundle.disclosed_turns[0].response = "I changed this response"
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False
        assert any("RESPONSE HASH MISMATCH" in c["detail"] for c in result.checks)

    def test_tampered_chain_record_hash(self, chain_3turns, vault_data):
        bundle = _make_bundle(chain_3turns, vault_data)
        bundle.chain_records[1]["record_hash"] = "f" * 64
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_broken_chain_link(self, chain_3turns, vault_data):
        bundle = _make_bundle(chain_3turns, vault_data)
        bundle.chain_records[2]["prev_hash"] = "0" * 64
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_tampered_anchor_hash(self, chain_3turns, vault_data):
        anchor = AnchorRef(
            anchor_type="sigstore",
            chain_head_hash="wrong_hash" + "0" * 54,
            reference="rekor-12345",
        )
        bundle = _make_bundle(chain_3turns, vault_data, anchors=[anchor])
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_swap_two_disclosed_turns(self, chain_3turns, vault_data):
        """Swapping the content of two disclosed turns should fail."""
        bundle = _make_bundle(chain_3turns, vault_data)
        # Swap prompts between turn 0 and turn 1
        bundle.disclosed_turns[0].prompt, bundle.disclosed_turns[1].prompt = (
            bundle.disclosed_turns[1].prompt, bundle.disclosed_turns[0].prompt,
        )
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_add_fake_disclosed_turn(self, chain_3turns, vault_data):
        """Adding a disclosed turn with wrong content should fail."""
        bundle = _make_bundle(chain_3turns, vault_data, disclose_seqs=[0, 1])
        # Add a fake disclosure for seq 2 with wrong content
        bundle.disclosed_turns.append(DisclosedTurn(
            seq=2,
            prompt="fake prompt",
            response="fake response",
            artifacts={},
        ))
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False


# ---------------------------------------------------------------------------
# Artifact verification in bundles
# ---------------------------------------------------------------------------

class TestBundleArtifacts:
    def test_artifact_in_bundle(self, tmp_path):
        """Artifact content in the bundle must match the chain hash."""
        artifact = tmp_path / "script.py"
        artifact.write_text("print('hello')")

        chain = Chain()
        chain.append_turn(
            prompt="write a script",
            response="here it is",
            artifact_paths=[artifact],
        )

        vault_data = {
            "0": {
                "prompt": "write a script",
                "response": "here it is",
                "artifacts": {"script.py": "print('hello')"},
            }
        }

        bundle = _make_bundle(chain, vault_data)
        result = verify_proof_bundle(bundle)
        assert result.is_valid is True

    def test_tampered_artifact(self, tmp_path):
        artifact = tmp_path / "script.py"
        artifact.write_text("print('hello')")

        chain = Chain()
        chain.append_turn(
            prompt="write a script",
            response="here it is",
            artifact_paths=[artifact],
        )

        vault_data = {
            "0": {
                "prompt": "write a script",
                "response": "here it is",
                "artifacts": {"script.py": "print('TAMPERED')"},
            }
        }

        bundle = _make_bundle(chain, vault_data)
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False
        assert any("ARTIFACT" in c["detail"] for c in result.checks)
