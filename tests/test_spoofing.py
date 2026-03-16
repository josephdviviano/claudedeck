"""
tests/test_spoofing.py — Spoofing and forgery attack tests.

These tests document attack vectors where a user could make it
appear that Claude produced output it never generated. Tests marked
"VULNERABILITY" demonstrate attacks that currently succeed — future
code fixes should cause these tests to change behavior.

Audit refs: C1 (no JSONL source validation), C2 (unauth hook stdin),
C3 (proof bundle forgery), H1 (fabricated fields)
"""

import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from claudedeck.core import (
    Chain, ChainRecord, TurnData, ArtifactRef,
    sha256_hex, canonical_json, generate_nonce, GENESIS_HASH,
)
from claudedeck.hook import (
    extract_turns, read_jsonl, main as hook_main,
    load_state, save_state, load_vault,
)
from claudedeck.proof import (
    ProofBundle, DisclosedTurn, AnchorRef, verify_proof_bundle,
)
from tests.conftest import make_session_jsonl


def _write_jsonl(path, records):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _run_hook(session_id, transcript_path, cwd):
    """Invoke the hook main() with crafted stdin."""
    hook_input = json.dumps({
        "session_id": session_id,
        "transcript_path": str(transcript_path),
        "cwd": str(cwd),
    })
    with patch("sys.stdin", io.StringIO(hook_input)):
        hook_main()


# ---------------------------------------------------------------------------
# VULNERABILITY: Forged session JSONL produces valid chains (C1)
# ---------------------------------------------------------------------------

class TestForgedSessionData:
    """An attacker can hand-craft session JSONL files with fabricated
    assistant turns. The hook trusts these files unconditionally."""

    def test_forged_assistant_response_chains_successfully(self, tmp_path):
        """VULNERABILITY: Fake assistant turns become valid chain records.

        Attack: Create a JSONL file with invented Claude responses,
        run the hook, get a cryptographically valid chain.
        """
        fake_turns = [
            ("Write harmful code", "Here is harmful code that steals data...", "claude-opus-4-6"),
        ]
        records = make_session_jsonl(fake_turns)
        transcript = tmp_path / "fake_transcript.jsonl"
        _write_jsonl(transcript, records)

        _run_hook("forged-session", transcript, tmp_path)

        chain_path = tmp_path / ".claudedeck" / "forged-session.chain.jsonl"
        assert chain_path.exists(), "Forged session produced a chain file"

        chain = Chain.load(chain_path)
        assert len(chain.records) == 1
        valid, errors = chain.verify()
        assert valid is True, f"Forged chain verifies as valid: {errors}"

    def test_forged_multi_turn_session(self, tmp_path):
        """VULNERABILITY: Multi-turn forged sessions create linked chains."""
        fake_turns = [
            ("Prompt 1", "Fake response 1", "claude-opus-4-6"),
            ("Prompt 2", "Fake response 2", "claude-opus-4-6"),
            ("Prompt 3", "Fake response 3", "claude-opus-4-6"),
        ]
        records = make_session_jsonl(fake_turns)
        transcript = tmp_path / "multi_turn.jsonl"
        _write_jsonl(transcript, records)

        _run_hook("multi-forged", transcript, tmp_path)

        chain = Chain.load(tmp_path / ".claudedeck" / "multi-forged.chain.jsonl")
        assert len(chain.records) == 3
        valid, errors = chain.verify()
        assert valid is True, "Multi-turn forged chain is fully valid"

        # All records are properly linked
        assert chain.records[0].prev_hash == GENESIS_HASH
        assert chain.records[1].prev_hash == chain.records[0].record_hash
        assert chain.records[2].prev_hash == chain.records[1].record_hash


# ---------------------------------------------------------------------------
# VULNERABILITY: Hook invocable with crafted stdin (C2)
# ---------------------------------------------------------------------------

class TestManualHookInvocation:
    """The hook reads JSON from stdin with no authentication.
    Anyone can invoke it with arbitrary input."""

    def test_hook_accepts_arbitrary_transcript_path(self, tmp_path):
        """VULNERABILITY: Hook processes any file path, not just Claude's."""
        # Create a JSONL file in a non-Claude location
        evil_jsonl = tmp_path / "evil.jsonl"
        records = make_session_jsonl([
            ("prompt", "I am Claude and I approve this message", "claude-opus-4-6"),
        ])
        _write_jsonl(evil_jsonl, records)

        _run_hook("hijacked", evil_jsonl, tmp_path)

        chain = Chain.load(tmp_path / ".claudedeck" / "hijacked.chain.jsonl")
        valid, _ = chain.verify()
        assert valid is True

    def test_hook_accepts_any_session_id(self, tmp_path):
        """VULNERABILITY: Session IDs are not validated."""
        records = make_session_jsonl([
            ("test", "response", "claude-opus-4-6"),
        ])
        transcript = tmp_path / "t.jsonl"
        _write_jsonl(transcript, records)

        # Use a session ID that looks like a real Claude session
        _run_hook("abc123-real-looking-session-id", transcript, tmp_path)

        chain_path = tmp_path / ".claudedeck" / "abc123-real-looking-session-id.chain.jsonl"
        assert chain_path.exists()


# ---------------------------------------------------------------------------
# VULNERABILITY: Proof bundles forgeable from scratch (C3)
# ---------------------------------------------------------------------------

class TestProofBundleForgery:
    """An attacker can create a valid proof bundle without ever
    having a Claude session."""

    def test_forge_complete_proof_bundle(self):
        """VULNERABILITY: Fabricate a proof bundle that passes verification.

        Attack: Create a chain and disclosed turns from scratch with
        matching hashes. No Claude session needed.
        """
        fake_prompt = "Write a function to hack the mainframe"
        fake_response = "Here's a function to hack the mainframe..."

        # Build a valid chain from scratch
        chain = Chain()
        chain.append_turn(
            prompt=fake_prompt,
            response=fake_response,
            model="claude-opus-4-6",
        )

        # Create proof bundle with "disclosed" content
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(
                seq=0,
                prompt=fake_prompt,
                response=fake_response,
                artifacts={},
            )],
            metadata={"researcher": "Attacker", "purpose": "Forgery"},
        )

        result = verify_proof_bundle(bundle)
        assert result.is_valid is True, (
            "Forged proof bundle passes verification — "
            "no session binding prevents complete forgery"
        )

    def test_forge_bundle_with_fake_anchors(self):
        """VULNERABILITY: Fake anchor references pass bundle verification."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        fake_anchor = AnchorRef(
            anchor_type="sigstore",
            chain_head_hash=chain.head_hash,
            reference="rekor:999999999",  # Doesn't exist
            timestamp="2026-03-16T00:00:00Z",
        )

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[],
            anchors=[fake_anchor],
        )

        result = verify_proof_bundle(bundle)
        # Anchor hash matches chain head, so it "passes"
        anchor_checks = [c for c in result.checks if "anchor_sigstore" in c["check"]]
        assert len(anchor_checks) == 1
        assert anchor_checks[0]["passed"] is True, (
            "Fake anchor reference passes verification because "
            "only hash matching is checked, not external validity"
        )

    def test_forge_bundle_roundtrip_through_file(self, tmp_path):
        """VULNERABILITY: Forged bundle survives save/load roundtrip."""
        chain = Chain()
        chain.append_turn(prompt="forged", response="content")

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(
                seq=0, prompt="forged", response="content", artifacts={},
            )],
        )

        bundle_path = tmp_path / "forged.proof.json"
        bundle.save(bundle_path)

        loaded = ProofBundle.load(bundle_path)
        result = verify_proof_bundle(loaded)
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# VULNERABILITY: Fabricated JSONL fields (H1)
# ---------------------------------------------------------------------------

class TestFabricatedFields:
    """Fields like promptId, stop_reason, requestId, and model are
    not validated against any authoritative source."""

    def test_fabricated_promptid_accepted(self):
        """VULNERABILITY: Any string works as a promptId."""
        records = [
            {
                "type": "user",
                "uuid": "u1",
                "parentUuid": None,
                "promptId": "TOTALLY_FAKE_PROMPT_ID",
                "message": {"role": "user", "content": "fake prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant",
                "uuid": "a1",
                "parentUuid": "u1",
                "message": {
                    "role": "assistant",
                    "model": "claude-opus-4-6",
                    "content": [{"type": "text", "text": "fake response"}],
                    "stop_reason": "end_turn",
                },
                "requestId": "FAKE_REQUEST_ID",
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["prompt"] == "fake prompt"
        assert turns[0]["response"] == "fake response"

    def test_fabricated_model_field_accepted(self):
        """VULNERABILITY: Model name is recorded verbatim, not validated."""
        records = make_session_jsonl([
            ("prompt", "response", "claude-nonexistent-model-9000"),
        ])
        turns = extract_turns(records)
        assert turns[0]["model"] == "claude-nonexistent-model-9000"

    def test_fabricated_request_id_recorded(self):
        """VULNERABILITY: requestId is stored without verification."""
        records = [
            {
                "type": "user",
                "uuid": "u1",
                "parentUuid": None,
                "promptId": "p1",
                "message": {"content": "prompt"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant",
                "uuid": "a1",
                "parentUuid": "u1",
                "message": {
                    "model": "claude-opus-4-6",
                    "content": [{"type": "text", "text": "response"}],
                    "stop_reason": "end_turn",
                },
                "requestId": "req_I_MADE_THIS_UP",
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert turns[0]["request_id"] == "req_I_MADE_THIS_UP"

    def test_fabricated_tool_use_blocks(self):
        """VULNERABILITY: Fake tool_use blocks are processed as real."""
        records = [
            {
                "type": "user",
                "uuid": "u1",
                "parentUuid": None,
                "promptId": "p1",
                "message": {"content": "do something"},
                "timestamp": "2026-03-15T12:00:00Z",
            },
            {
                "type": "assistant",
                "uuid": "a1",
                "parentUuid": "u1",
                "message": {
                    "model": "claude-opus-4-6",
                    "content": [
                        {"type": "text", "text": "I'll write that file"},
                        {
                            "type": "tool_use",
                            "id": "toolu_FAKE",
                            "name": "Write",
                            "input": {
                                "file_path": "/etc/passwd",
                                "content": "root::0:0:::",
                            },
                        },
                    ],
                    "stop_reason": "end_turn",
                },
                "requestId": "req_fake",
                "timestamp": "2026-03-15T12:00:05Z",
            },
        ]
        turns = extract_turns(records)
        assert "Write" in turns[0]["tool_calls"]
        assert any(
            op["file_path"] == "/etc/passwd"
            for op in turns[0]["file_operations"]
        )


# ---------------------------------------------------------------------------
# VULNERABILITY: Selective disclosure misrepresentation (H5)
# ---------------------------------------------------------------------------

class TestSelectiveDisclosureMisuse:
    """Selective disclosure is by-design, but can be used to
    misrepresent the conversation context."""

    def test_hiding_contradiction_between_turns(self):
        """VULNERABILITY: Omitting turns can hide important context.

        A researcher discloses turns 0 and 2 but hides turn 1 where
        the model corrected itself. Readers see agreement without
        the retraction.
        """
        chain = Chain()
        chain.append_turn(
            prompt="Is X always true?",
            response="Yes, X is always true.",
        )
        chain.append_turn(
            prompt="But what about edge case Y?",
            response="You're right, I was wrong. X is NOT always true when Y applies.",
        )
        chain.append_turn(
            prompt="So what's the correct statement?",
            response="The correct statement accounts for Y.",
        )

        # Disclose only turns 0 and 2, hiding the contradiction
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[
                DisclosedTurn(
                    seq=0,
                    prompt="Is X always true?",
                    response="Yes, X is always true.",
                    artifacts={},
                ),
                DisclosedTurn(
                    seq=2,
                    prompt="So what's the correct statement?",
                    response="The correct statement accounts for Y.",
                    artifacts={},
                ),
            ],
        )

        result = verify_proof_bundle(bundle)
        assert result.is_valid is True, (
            "Bundle with misleading selective disclosure passes verification"
        )
        # All 3 chain records present, but only 2 disclosed
        assert len(bundle.chain_records) == 3
        assert len(bundle.disclosed_turns) == 2


# ---------------------------------------------------------------------------
# Defense tests: things that SHOULD be caught
# ---------------------------------------------------------------------------

class TestSpoofingDefenses:
    """Tests for existing defenses that DO catch tampering."""

    def test_tampered_disclosed_prompt_detected(self):
        """DEFENSE: Modifying disclosed prompt text is detected."""
        chain = Chain()
        chain.append_turn(prompt="real prompt", response="real response")

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(
                seq=0,
                prompt="TAMPERED prompt",  # Doesn't match hash
                response="real response",
                artifacts={},
            )],
        )

        result = verify_proof_bundle(bundle)
        assert result.is_valid is False
        assert any("MISMATCH" in c["detail"] for c in result.checks if not c["passed"])

    def test_tampered_disclosed_response_detected(self):
        """DEFENSE: Modifying disclosed response text is detected."""
        chain = Chain()
        chain.append_turn(prompt="real prompt", response="real response")

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(
                seq=0,
                prompt="real prompt",
                response="TAMPERED response",
                artifacts={},
            )],
        )

        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_tampered_chain_record_hash_detected(self):
        """DEFENSE: Modifying a record_hash breaks verification."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        records_dicts = [r.to_dict() for r in chain.records]
        records_dicts[0]["record_hash"] = "a" * 64

        bundle = ProofBundle(chain_records=records_dicts, disclosed_turns=[])
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_chain_linkage_break_detected(self):
        """DEFENSE: Breaking prev_hash linkage is detected."""
        chain = Chain()
        chain.append_turn(prompt="p1", response="r1")
        chain.append_turn(prompt="p2", response="r2")

        records_dicts = [r.to_dict() for r in chain.records]
        records_dicts[1]["prev_hash"] = "b" * 64

        bundle = ProofBundle(chain_records=records_dicts, disclosed_turns=[])
        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_disclosed_seq_not_in_chain_detected(self):
        """DEFENSE: Disclosing a seq that doesn't exist in chain is caught."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(
                seq=99, prompt="p", response="r", artifacts={},
            )],
        )

        result = verify_proof_bundle(bundle)
        assert result.is_valid is False

    def test_anchor_hash_mismatch_detected(self):
        """DEFENSE: Anchor pointing to wrong chain head is caught."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r")

        bad_anchor = AnchorRef(
            anchor_type="local",
            chain_head_hash="c" * 64,  # Wrong hash
            reference="local:fake",
        )

        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[],
            anchors=[bad_anchor],
        )

        result = verify_proof_bundle(bundle)
        assert result.is_valid is False
