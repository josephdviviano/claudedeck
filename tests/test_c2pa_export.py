"""Tests for claudedeck.c2pa_export — C2PA manifest generation and verification."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from claudedeck.core import Chain
from claudedeck.proof import ProofBundle, DisclosedTurn, AnchorRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bundle(num_turns=2, disclosed_seqs=None, anchors=None, metadata=None, model=None):
    """Create a test chain and proof bundle."""
    chain = Chain()
    prompts = [f"prompt_{i}" for i in range(num_turns)]
    responses = [f"response_{i}" for i in range(num_turns)]

    for i in range(num_turns):
        chain.append_turn(prompt=prompts[i], response=responses[i], model=model)

    if disclosed_seqs is None:
        disclosed_seqs = list(range(num_turns))

    disclosed = [
        DisclosedTurn(
            seq=i, prompt=prompts[i], response=responses[i], artifacts={}
        )
        for i in disclosed_seqs
    ]

    bundle = ProofBundle(
        chain_records=[r.to_dict() for r in chain.records],
        disclosed_turns=disclosed,
        anchors=anchors or [],
        metadata=metadata or {},
    )
    return chain, bundle


def _save_bundle(bundle, tmp_path):
    """Save a bundle and return its path."""
    path = tmp_path / "test.proof.json"
    bundle.save(path)
    return path


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

class TestCertGeneration:
    def test_generates_valid_pem(self):
        from claudedeck.c2pa_export import _generate_cert_chain

        cert_chain, private_key = _generate_cert_chain()
        assert b"BEGIN CERTIFICATE" in cert_chain
        assert b"END CERTIFICATE" in cert_chain
        assert b"BEGIN PRIVATE KEY" in private_key
        assert b"END PRIVATE KEY" in private_key

    def test_chain_has_two_certs(self):
        from claudedeck.c2pa_export import _generate_cert_chain

        cert_chain, _ = _generate_cert_chain()
        # Should contain leaf + CA = 2 certificates
        assert cert_chain.count(b"BEGIN CERTIFICATE") == 2

    def test_certs_are_different_each_time(self):
        from claudedeck.c2pa_export import _generate_cert_chain

        chain1, key1 = _generate_cert_chain()
        chain2, key2 = _generate_cert_chain()
        assert chain1 != chain2
        assert key1 != key2


# ---------------------------------------------------------------------------
# Manifest construction
# ---------------------------------------------------------------------------

class TestManifestConstruction:
    def test_basic_manifest_structure(self):
        from claudedeck.c2pa_export import _build_manifest_json

        _, bundle = _make_bundle()
        manifest = _build_manifest_json(bundle)

        assert "claim_generator" in manifest
        assert "claudedeck" in manifest["claim_generator"]
        assert "assertions" in manifest
        assert manifest["title"] == "claudedeck proof bundle"

    def test_manifest_has_creative_work_assertion(self):
        from claudedeck.c2pa_export import _build_manifest_json

        _, bundle = _make_bundle()
        manifest = _build_manifest_json(bundle)
        labels = [a["label"] for a in manifest["assertions"]]
        assert "stds.schema-org.CreativeWork" in labels

    def test_manifest_has_actions_assertion(self):
        from claudedeck.c2pa_export import _build_manifest_json

        _, bundle = _make_bundle()
        manifest = _build_manifest_json(bundle)
        actions_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "c2pa.actions"
        )
        actions = actions_assertion["data"]["actions"]
        assert len(actions) == 2
        assert actions[0]["action"] == "c2pa.created"
        assert actions[1]["action"] == "c2pa.edited"

    def test_manifest_has_chain_assertion(self):
        from claudedeck.c2pa_export import _build_manifest_json

        chain, bundle = _make_bundle()
        manifest = _build_manifest_json(bundle)
        chain_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "org.claudedeck.chain"
        )
        data = chain_assertion["data"]
        assert data["chain_head_hash"] == chain.head_hash
        assert data["num_records"] == "2"
        assert data["disclosed_sequences"] == "0,1"

    def test_manifest_chain_with_partial_disclosure(self):
        from claudedeck.c2pa_export import _build_manifest_json

        _, bundle = _make_bundle(num_turns=5, disclosed_seqs=[1, 3])
        manifest = _build_manifest_json(bundle)
        chain_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "org.claudedeck.chain"
        )
        assert chain_assertion["data"]["disclosed_sequences"] == "1,3"
        assert chain_assertion["data"]["num_records"] == "5"

    def test_manifest_includes_anchors(self):
        from claudedeck.c2pa_export import _build_manifest_json

        chain, _ = _make_bundle()
        anchors = [
            AnchorRef(anchor_type="local", chain_head_hash=chain.head_hash, reference="local:0"),
            AnchorRef(anchor_type="sigstore", chain_head_hash=chain.head_hash, reference="rekor:99"),
        ]
        _, bundle = _make_bundle(anchors=anchors)
        manifest = _build_manifest_json(bundle)
        chain_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "org.claudedeck.chain"
        )
        anchors_json = json.loads(chain_assertion["data"]["anchors"])
        assert len(anchors_json) == 2

    def test_manifest_includes_metadata(self):
        from claudedeck.c2pa_export import _build_manifest_json

        _, bundle = _make_bundle(metadata={"researcher": "Alice", "orcid": "0000-0001"})
        manifest = _build_manifest_json(bundle)
        chain_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "org.claudedeck.chain"
        )
        metadata = json.loads(chain_assertion["data"]["metadata"])
        assert metadata["researcher"] == "Alice"

    def test_manifest_model_in_actions(self):
        from claudedeck.c2pa_export import _build_manifest_json

        _, bundle = _make_bundle(model="claude-opus-4-20250514")
        manifest = _build_manifest_json(bundle)
        actions_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "c2pa.actions"
        )
        action = actions_assertion["data"]["actions"][0]
        assert action["softwareAgent"]["model"] == "claude-opus-4-20250514"

    def test_manifest_empty_chain(self):
        from claudedeck.c2pa_export import _build_manifest_json

        bundle = ProofBundle(chain_records=[], disclosed_turns=[])
        manifest = _build_manifest_json(bundle)
        chain_assertion = next(
            a for a in manifest["assertions"] if a["label"] == "org.claudedeck.chain"
        )
        assert chain_assertion["data"]["chain_head_hash"] == ""
        assert chain_assertion["data"]["num_records"] == "0"


# ---------------------------------------------------------------------------
# PNG generation
# ---------------------------------------------------------------------------

class TestMinimalPng:
    def test_valid_png_header(self):
        from claudedeck.c2pa_export import _make_minimal_png

        png = _make_minimal_png()
        assert png[:8] == b"\x89PNG\r\n\x1a\n"

    def test_png_has_ihdr_idat_iend(self):
        from claudedeck.c2pa_export import _make_minimal_png

        png = _make_minimal_png()
        assert b"IHDR" in png
        assert b"IDAT" in png
        assert b"IEND" in png

    def test_png_reasonable_size(self):
        from claudedeck.c2pa_export import _make_minimal_png

        png = _make_minimal_png()
        # A 1x1 PNG should be small
        assert 50 < len(png) < 200


# ---------------------------------------------------------------------------
# Export (end-to-end, requires c2pa-python)
# ---------------------------------------------------------------------------

class TestExportC2pa:
    def test_export_basic(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success is True
        assert result.error is None
        assert result.manifest_path is not None
        assert Path(result.manifest_path).exists()

    def test_export_default_output_path(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.manifest_path == str(bundle_path.with_suffix(".c2pa.png"))

    def test_export_custom_output_path(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)
        custom_path = tmp_path / "custom.c2pa.png"

        result = export_c2pa_manifest(bundle, bundle_path, output_path=custom_path)
        assert result.success is True
        assert result.manifest_path == str(custom_path)
        assert custom_path.exists()

    def test_export_with_anchors(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        chain, _ = _make_bundle()
        anchors = [
            AnchorRef(anchor_type="local", chain_head_hash=chain.head_hash, reference="local:0"),
        ]
        _, bundle = _make_bundle(anchors=anchors)
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success is True

    def test_export_with_metadata(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle(metadata={"researcher": "test"})
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success is True

    def test_export_with_custom_certs(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, _generate_cert_chain

        _, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)
        cert_chain, priv_key = _generate_cert_chain()

        result = export_c2pa_manifest(
            bundle, bundle_path,
            cert_chain_pem=cert_chain,
            private_key_pem=priv_key,
        )
        assert result.success is True

    def test_export_cert_without_key_fails(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, _generate_cert_chain

        _, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)
        cert_chain, _ = _generate_cert_chain()

        result = export_c2pa_manifest(
            bundle, bundle_path,
            cert_chain_pem=cert_chain,
        )
        assert result.success is False
        assert "private_key_pem required" in result.error

    def test_export_missing_c2pa(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        with patch.dict("sys.modules", {"c2pa": None}):
            # Need to reimport to trigger the ImportError
            import importlib
            import claudedeck.c2pa_export
            importlib.reload(claudedeck.c2pa_export)

            # The function catches ImportError internally
            result = claudedeck.c2pa_export.export_c2pa_manifest(bundle, bundle_path)

        # Reload to restore
        import claudedeck.c2pa_export
        importlib.reload(claudedeck.c2pa_export)

        assert result.success is False
        assert "not installed" in result.error

    def test_export_single_turn(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle(num_turns=1)
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success is True

    def test_export_many_turns(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle(num_turns=20)
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success is True

    def test_export_partial_disclosure(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest

        _, bundle = _make_bundle(num_turns=5, disclosed_seqs=[0, 4])
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success is True


# ---------------------------------------------------------------------------
# Read manifest
# ---------------------------------------------------------------------------

class TestReadManifest:
    def test_read_exported_manifest(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, read_c2pa_manifest

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success

        store = read_c2pa_manifest(result.manifest_path)
        assert store is not None
        assert "active_manifest" in store
        assert "manifests" in store

    def test_read_has_chain_assertion(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, read_c2pa_manifest

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        store = read_c2pa_manifest(result.manifest_path)

        active = store["manifests"][store["active_manifest"]]
        labels = [a["label"] for a in active["assertions"]]
        assert "org.claudedeck.chain" in labels

    def test_read_chain_head_matches(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, read_c2pa_manifest

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        store = read_c2pa_manifest(result.manifest_path)

        active = store["manifests"][store["active_manifest"]]
        chain_data = next(
            a["data"] for a in active["assertions"]
            if a["label"] == "org.claudedeck.chain"
        )
        assert chain_data["chain_head_hash"] == chain.head_hash

    def test_read_disclosed_sequences(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, read_c2pa_manifest

        _, bundle = _make_bundle(num_turns=5, disclosed_seqs=[1, 3])
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        store = read_c2pa_manifest(result.manifest_path)

        active = store["manifests"][store["active_manifest"]]
        chain_data = next(
            a["data"] for a in active["assertions"]
            if a["label"] == "org.claudedeck.chain"
        )
        assert chain_data["disclosed_sequences"] == "1,3"

    def test_read_nonexistent_file(self, tmp_path):
        from claudedeck.c2pa_export import read_c2pa_manifest

        with pytest.raises(Exception):
            read_c2pa_manifest(tmp_path / "nonexistent.c2pa.png")


# ---------------------------------------------------------------------------
# Verify manifest
# ---------------------------------------------------------------------------

class TestVerifyManifest:
    def test_verify_valid(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, verify_c2pa_manifest

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        ok, detail = verify_c2pa_manifest(result.manifest_path)
        assert ok is True
        assert "valid" in detail.lower()

    def test_verify_with_correct_chain_head(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, verify_c2pa_manifest

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        ok, detail = verify_c2pa_manifest(result.manifest_path, chain.head_hash)
        assert ok is True

    def test_verify_with_wrong_chain_head(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, verify_c2pa_manifest

        _, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        ok, detail = verify_c2pa_manifest(result.manifest_path, "f" * 64)
        assert ok is False
        assert "mismatch" in detail.lower()

    def test_verify_nonexistent_file(self, tmp_path):
        from claudedeck.c2pa_export import verify_c2pa_manifest

        ok, detail = verify_c2pa_manifest(tmp_path / "nonexistent.c2pa.png")
        assert ok is False
        assert "Failed" in detail

    def test_verify_corrupted_file(self, tmp_path):
        from claudedeck.c2pa_export import verify_c2pa_manifest

        bad_file = tmp_path / "bad.c2pa.png"
        bad_file.write_bytes(b"not a png")

        ok, detail = verify_c2pa_manifest(bad_file)
        assert ok is False


# ---------------------------------------------------------------------------
# Extract chain assertion helper
# ---------------------------------------------------------------------------

class TestExtractChainAssertion:
    def test_extract_from_valid_store(self, tmp_path):
        from claudedeck.c2pa_export import (
            export_c2pa_manifest, read_c2pa_manifest, _extract_chain_assertion,
        )

        chain, bundle = _make_bundle()
        bundle_path = _save_bundle(bundle, tmp_path)
        result = export_c2pa_manifest(bundle, bundle_path)
        store = read_c2pa_manifest(result.manifest_path)

        data = _extract_chain_assertion(store)
        assert data is not None
        assert data["chain_head_hash"] == chain.head_hash

    def test_extract_from_empty_store(self):
        from claudedeck.c2pa_export import _extract_chain_assertion

        assert _extract_chain_assertion({}) is None
        assert _extract_chain_assertion({"active_manifest": None}) is None

    def test_extract_no_chain_assertion(self):
        from claudedeck.c2pa_export import _extract_chain_assertion

        store = {
            "active_manifest": "test",
            "manifests": {
                "test": {"assertions": [{"label": "other", "data": {}}]}
            },
        }
        assert _extract_chain_assertion(store) is None


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestCLIC2pa:
    def test_proof_with_c2pa_flag(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.save(deck_dir / "test-session.chain.jsonl")
        vault = {"0": {"prompt": "hello", "response": "world"}}
        with open(deck_dir / "test-session.vault.json", "w") as f:
            json.dump(vault, f)

        from claudedeck.__main__ import cmd_proof

        args = type("Args", (), {
            "session": "test-session",
            "seqs": None,
            "output": str(deck_dir / "test.proof.json"),
            "no_anchors": True,
            "c2pa": True,
        })()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_proof(args)

        output = capsys.readouterr().out
        assert "C2PA manifest:" in output
        assert Path(deck_dir / "test.proof.c2pa.png").exists()

    def test_proof_without_c2pa_flag(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.save(deck_dir / "test-session.chain.jsonl")
        vault = {"0": {"prompt": "hello", "response": "world"}}
        with open(deck_dir / "test-session.vault.json", "w") as f:
            json.dump(vault, f)

        from claudedeck.__main__ import cmd_proof

        args = type("Args", (), {
            "session": "test-session",
            "seqs": None,
            "output": str(deck_dir / "test.proof.json"),
            "no_anchors": True,
            "c2pa": False,
        })()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_proof(args)

        output = capsys.readouterr().out
        assert "C2PA" not in output

    def test_c2pa_verify_command(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.save(deck_dir / "test-session.chain.jsonl")

        # Create a proof bundle and C2PA manifest
        from claudedeck.proof import ProofBundle, DisclosedTurn
        from claudedeck.c2pa_export import export_c2pa_manifest

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(seq=0, prompt="hello", response="world", artifacts={})],
        )
        bundle_path = deck_dir / "test-session.proof.json"
        bundle.save(bundle_path)
        export_c2pa_manifest(bundle, bundle_path)

        from claudedeck.__main__ import cmd_c2pa_verify

        args = type("Args", (), {
            "session": "test-session",
            "manifest": None,
        })()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_c2pa_verify(args)

        output = capsys.readouterr().out
        assert "VALID" in output

    def test_c2pa_verify_with_manifest_path(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.save(deck_dir / "test-session.chain.jsonl")

        from claudedeck.proof import ProofBundle, DisclosedTurn
        from claudedeck.c2pa_export import export_c2pa_manifest

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(seq=0, prompt="hello", response="world", artifacts={})],
        )
        bundle_path = deck_dir / "test-session.proof.json"
        bundle.save(bundle_path)
        result = export_c2pa_manifest(bundle, bundle_path)

        from claudedeck.__main__ import cmd_c2pa_verify

        args = type("Args", (), {
            "session": "test-session",
            "manifest": result.manifest_path,
        })()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_c2pa_verify(args)

        output = capsys.readouterr().out
        assert "VALID" in output

    def test_c2pa_verify_missing_manifest(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.save(deck_dir / "test-session.chain.jsonl")

        from claudedeck.__main__ import cmd_c2pa_verify

        args = type("Args", (), {
            "session": "test-session",
            "manifest": None,
        })()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            with pytest.raises(SystemExit):
                cmd_c2pa_verify(args)


# ---------------------------------------------------------------------------
# Roundtrip: chain → bundle → C2PA → verify
# ---------------------------------------------------------------------------

class TestRoundtrip:
    def test_full_roundtrip(self, tmp_path):
        from claudedeck.c2pa_export import (
            export_c2pa_manifest, read_c2pa_manifest, verify_c2pa_manifest,
        )

        chain, bundle = _make_bundle(num_turns=3, model="claude-opus-4-20250514")
        bundle_path = _save_bundle(bundle, tmp_path)

        # Export
        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success

        # Read
        store = read_c2pa_manifest(result.manifest_path)
        assert store is not None

        # Verify
        ok, detail = verify_c2pa_manifest(result.manifest_path, chain.head_hash)
        assert ok is True

        # Check assertions preserved
        active = store["manifests"][store["active_manifest"]]
        chain_data = next(
            a["data"] for a in active["assertions"]
            if a["label"] == "org.claudedeck.chain"
        )
        assert chain_data["chain_head_hash"] == chain.head_hash
        assert chain_data["num_records"] == "3"
        assert chain_data["disclosed_sequences"] == "0,1,2"

    def test_roundtrip_with_anchors_and_metadata(self, tmp_path):
        from claudedeck.c2pa_export import (
            export_c2pa_manifest, read_c2pa_manifest, verify_c2pa_manifest,
        )

        chain, _ = _make_bundle()
        anchors = [
            AnchorRef(
                anchor_type="sigstore",
                chain_head_hash=chain.head_hash,
                reference="rekor:12345",
                timestamp="2026-03-16T00:00:00Z",
            ),
        ]
        _, bundle = _make_bundle(
            anchors=anchors,
            metadata={"researcher": "Alice", "purpose": "reproducibility"},
        )
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success

        store = read_c2pa_manifest(result.manifest_path)
        active = store["manifests"][store["active_manifest"]]
        chain_data = next(
            a["data"] for a in active["assertions"]
            if a["label"] == "org.claudedeck.chain"
        )

        anchors_json = json.loads(chain_data["anchors"])
        assert len(anchors_json) == 1
        assert anchors_json[0]["anchor_type"] == "sigstore"

        metadata = json.loads(chain_data["metadata"])
        assert metadata["researcher"] == "Alice"

        ok, _ = verify_c2pa_manifest(result.manifest_path)
        assert ok is True

    def test_roundtrip_selective_disclosure(self, tmp_path):
        from claudedeck.c2pa_export import export_c2pa_manifest, read_c2pa_manifest

        _, bundle = _make_bundle(num_turns=10, disclosed_seqs=[2, 5, 7])
        bundle_path = _save_bundle(bundle, tmp_path)

        result = export_c2pa_manifest(bundle, bundle_path)
        assert result.success

        store = read_c2pa_manifest(result.manifest_path)
        active = store["manifests"][store["active_manifest"]]
        chain_data = next(
            a["data"] for a in active["assertions"]
            if a["label"] == "org.claudedeck.chain"
        )
        assert chain_data["disclosed_sequences"] == "2,5,7"
        assert chain_data["num_records"] == "10"
