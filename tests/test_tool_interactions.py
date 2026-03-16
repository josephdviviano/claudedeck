"""Tests for tool interaction capture and verification.

Verifies that tool inputs (parameters) and tool results (output) are
cryptographically bound to the hash chain, so the full information flow
that informed AI decisions is verifiable.
"""

import json
import pytest

from claudedeck.core import (
    Chain, ToolInteraction, sha256_hex, canonical_json,
)
from claudedeck.proof import (
    ProofBundle, DisclosedTurn, DisclosedToolInteraction,
    verify_proof_bundle,
)
from claudedeck.hook import (
    extract_tool_results, build_tool_interactions, extract_turns,
)
from tests.conftest import make_tool_use_session, make_multi_tool_session


# ---------------------------------------------------------------------------
# ToolInteraction dataclass
# ---------------------------------------------------------------------------

class TestToolInteraction:
    def test_from_plaintext_hashes_input_and_result(self):
        ti = ToolInteraction.from_plaintext(
            tool_name="Read",
            tool_use_id="toolu_001",
            input_params={"file_path": "/config.json"},
            result_content='{"key": "value"}',
        )
        assert ti.tool_name == "Read"
        assert ti.tool_use_id == "toolu_001"
        assert ti.input_hash == sha256_hex(canonical_json({"file_path": "/config.json"}))
        assert ti.result_hash == sha256_hex('{"key": "value"}'.encode("utf-8"))

    def test_roundtrip_dict(self):
        ti = ToolInteraction.from_plaintext(
            tool_name="Bash",
            tool_use_id="toolu_002",
            input_params={"command": "ls -la"},
            result_content="total 42\ndrwxr-xr-x ...",
        )
        d = ti.to_dict()
        ti2 = ToolInteraction.from_dict(d)
        assert ti2.tool_name == ti.tool_name
        assert ti2.tool_use_id == ti.tool_use_id
        assert ti2.input_hash == ti.input_hash
        assert ti2.result_hash == ti.result_hash

    def test_different_inputs_produce_different_hashes(self):
        ti1 = ToolInteraction.from_plaintext(
            "Read", "t1", {"file_path": "/a.txt"}, "content a",
        )
        ti2 = ToolInteraction.from_plaintext(
            "Read", "t2", {"file_path": "/b.txt"}, "content b",
        )
        assert ti1.input_hash != ti2.input_hash
        assert ti1.result_hash != ti2.result_hash

    def test_empty_result_is_valid(self):
        """Tools that return nothing should still produce a valid hash."""
        ti = ToolInteraction.from_plaintext(
            "Write", "t1", {"file_path": "/out.txt", "content": "hi"}, "",
        )
        assert ti.result_hash == sha256_hex(b"")


# ---------------------------------------------------------------------------
# Hook extraction
# ---------------------------------------------------------------------------

class TestExtractToolResults:
    def test_extracts_tool_result_content(self):
        records = make_tool_use_session()
        results = extract_tool_results(records, "user-0001", None)
        assert "toolu_001" in results
        assert results["toolu_001"] == '{"key": "value"}'

    def test_skips_real_user_messages(self):
        """Messages with promptId should not be treated as tool results."""
        records = make_tool_use_session()
        results = extract_tool_results(records, "user-0001", None)
        # Only one tool result, not the user prompt
        assert len(results) == 1

    def test_multi_tool_results(self):
        records = make_multi_tool_session()
        results = extract_tool_results(records, "user-0001", None)
        assert "toolu_001" in results
        assert "toolu_002" in results
        assert results["toolu_001"] == "db_host: localhost\ndb_port: 5432"
        assert results["toolu_002"] == "File written successfully."

    def test_empty_when_no_tools(self):
        records = [
            {
                "type": "user", "uuid": "u1", "promptId": "p1",
                "message": {"role": "user", "content": "hello"},
            },
            {
                "type": "assistant", "uuid": "a1", "parentUuid": "u1",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hi"}],
                    "stop_reason": "end_turn", "model": "test",
                },
            },
        ]
        results = extract_tool_results(records, "u1", None)
        assert results == {}

    def test_list_content_in_tool_result(self):
        """Tool results can have list-of-blocks content."""
        records = [
            {"type": "user", "uuid": "u1", "promptId": "p1",
             "message": {"role": "user", "content": "test"}},
            {"type": "assistant", "uuid": "a1", "parentUuid": "u1",
             "message": {"role": "assistant", "model": "test",
                         "content": [{"type": "tool_use", "id": "t1", "name": "Read",
                                      "input": {"file_path": "/x"}}],
                         "stop_reason": None}},
            {"type": "user", "uuid": "u2", "parentUuid": "a1",
             "message": {"role": "user",
                         "content": [{"tool_use_id": "t1", "type": "tool_result",
                                      "content": [{"type": "text", "text": "line1"},
                                                   {"type": "text", "text": "line2"}]}]}},
        ]
        results = extract_tool_results(records, "u1", None)
        assert results["t1"] == "line1\nline2"


class TestBuildToolInteractions:
    def test_pairs_inputs_with_results(self):
        tool_calls = [
            {"name": "Read", "id": "toolu_001", "input": {"file_path": "/config.json"}},
        ]
        tool_results = {"toolu_001": '{"key": "value"}'}
        interactions = build_tool_interactions(tool_calls, tool_results)
        assert len(interactions) == 1
        ti = interactions[0]
        assert ti.tool_name == "Read"
        assert ti.tool_use_id == "toolu_001"
        assert ti.input_hash == sha256_hex(canonical_json({"file_path": "/config.json"}))
        assert ti.result_hash == sha256_hex(b'{"key": "value"}')

    def test_missing_result_uses_empty_string(self):
        """If a tool result relay is missing, hash empty string."""
        tool_calls = [
            {"name": "Write", "id": "toolu_999", "input": {"file_path": "/out.txt"}},
        ]
        interactions = build_tool_interactions(tool_calls, {})
        assert len(interactions) == 1
        assert interactions[0].result_hash == sha256_hex(b"")

    def test_skips_tool_calls_without_id(self):
        tool_calls = [
            {"name": "Read", "id": "", "input": {}},
            {"name": "Read", "input": {}},  # no id key
        ]
        interactions = build_tool_interactions(tool_calls, {})
        assert len(interactions) == 0


# ---------------------------------------------------------------------------
# Chain integration
# ---------------------------------------------------------------------------

class TestChainWithToolInteractions:
    def test_tool_interactions_included_in_hash(self):
        """Modifying a tool interaction should change the record hash."""
        chain1 = Chain()
        ti = ToolInteraction.from_plaintext("Read", "t1", {"file_path": "/a"}, "content")
        chain1.append_turn(
            prompt="test", response="resp",
            tool_interactions=[ti], model="test",
        )

        chain2 = Chain(chain_id=chain1.chain_id)
        ti_modified = ToolInteraction.from_plaintext("Read", "t1", {"file_path": "/b"}, "content")
        chain2.append_turn(
            prompt="test", response="resp",
            tool_interactions=[ti_modified], model="test",
        )
        # Nonces differ so hashes always differ, but let's verify the turn data differs
        assert chain1.records[0].turn.tool_interactions[0].input_hash != \
               chain2.records[0].turn.tool_interactions[0].input_hash

    def test_chain_verify_with_tool_interactions(self):
        chain = Chain()
        ti = ToolInteraction.from_plaintext("Read", "t1", {"path": "/x"}, "result")
        chain.append_turn(prompt="p", response="r", tool_interactions=[ti])
        valid, errors = chain.verify()
        assert valid, errors

    def test_backward_compat_no_tool_interactions(self):
        """Chains without tool_interactions should still verify."""
        chain = Chain()
        chain.append_turn(prompt="p", response="r", model="test")
        valid, errors = chain.verify()
        assert valid, errors

    def test_save_load_roundtrip(self, tmp_path):
        chain = Chain()
        ti = ToolInteraction.from_plaintext("Bash", "t1", {"command": "ls"}, "file1\nfile2")
        chain.append_turn(prompt="list files", response="done", tool_interactions=[ti])
        path = tmp_path / "test.chain.jsonl"
        chain.save(path)

        loaded = Chain.load(path)
        assert len(loaded.records) == 1
        assert len(loaded.records[0].turn.tool_interactions) == 1
        loaded_ti = loaded.records[0].turn.tool_interactions[0]
        assert loaded_ti.tool_name == "Bash"
        assert loaded_ti.input_hash == ti.input_hash
        assert loaded_ti.result_hash == ti.result_hash
        valid, errors = loaded.verify()
        assert valid, errors


# ---------------------------------------------------------------------------
# Proof bundle verification
# ---------------------------------------------------------------------------

class TestProofBundleToolInteractions:
    def _make_bundle_with_tools(self):
        """Helper: create a chain + bundle with tool interactions."""
        chain = Chain()
        ti = ToolInteraction.from_plaintext(
            "Read", "toolu_001",
            {"file_path": "/config.json"},
            '{"key": "value"}',
        )
        chain.append_turn(
            prompt="Read my config",
            response="Your config has key=value.",
            tool_interactions=[ti],
            tool_calls=["Read"],
            model="test",
        )
        disclosed = DisclosedTurn(
            seq=0,
            prompt="Read my config",
            response="Your config has key=value.",
            artifacts={},
            tool_interactions=[
                DisclosedToolInteraction(
                    tool_name="Read",
                    tool_use_id="toolu_001",
                    input={"file_path": "/config.json"},
                    result='{"key": "value"}',
                ),
            ],
        )
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[disclosed],
        )
        return bundle

    def test_valid_tool_interactions_verify(self):
        bundle = self._make_bundle_with_tools()
        result = verify_proof_bundle(bundle)
        assert result.is_valid, result.summary()

    def test_tampered_tool_input_detected(self):
        bundle = self._make_bundle_with_tools()
        bundle.disclosed_turns[0].tool_interactions[0].input = {"file_path": "/HACKED"}
        result = verify_proof_bundle(bundle)
        assert not result.is_valid
        assert any("TOOL INPUT HASH MISMATCH" in c["detail"] for c in result.checks)

    def test_tampered_tool_result_detected(self):
        bundle = self._make_bundle_with_tools()
        bundle.disclosed_turns[0].tool_interactions[0].result = "FAKE RESULT"
        result = verify_proof_bundle(bundle)
        assert not result.is_valid
        assert any("TOOL RESULT HASH MISMATCH" in c["detail"] for c in result.checks)

    def test_extra_tool_interaction_detected(self):
        bundle = self._make_bundle_with_tools()
        bundle.disclosed_turns[0].tool_interactions.append(
            DisclosedToolInteraction(
                tool_name="Bash",
                tool_use_id="toolu_FAKE",
                input={"command": "rm -rf /"},
                result="",
            )
        )
        result = verify_proof_bundle(bundle)
        assert not result.is_valid
        assert any("not in chain record" in c["detail"] for c in result.checks)

    def test_bundle_without_tool_interactions_still_valid(self):
        """Backward compat: bundles with no tool_interactions verify fine."""
        chain = Chain()
        chain.append_turn(prompt="hi", response="hello", model="test")
        bundle = ProofBundle(
            chain_records=[r.to_dict() for r in chain.records],
            disclosed_turns=[DisclosedTurn(
                seq=0, prompt="hi", response="hello", artifacts={},
            )],
        )
        result = verify_proof_bundle(bundle)
        assert result.is_valid, result.summary()

    def test_save_load_bundle_with_tools(self, tmp_path):
        bundle = self._make_bundle_with_tools()
        path = tmp_path / "test.proof.json"
        bundle.save(path)
        loaded = ProofBundle.load(path)
        result = verify_proof_bundle(loaded)
        assert result.is_valid, result.summary()
        assert len(loaded.disclosed_turns[0].tool_interactions) == 1


# ---------------------------------------------------------------------------
# Full pipeline: extract_turns with tool I/O
# ---------------------------------------------------------------------------

class TestExtractTurnsWithToolIO:
    def test_single_tool_turn(self):
        records = make_tool_use_session()
        turns = extract_turns(records)
        assert len(turns) == 1
        turn = turns[0]
        assert len(turn["tool_interactions"]) == 1
        ti = turn["tool_interactions"][0]
        assert ti.tool_name == "Read"
        assert ti.tool_use_id == "toolu_001"
        # Verify the plaintext data for vault storage
        assert len(turn["tool_io_plaintext"]) == 1
        assert turn["tool_io_plaintext"][0]["input"] == {"file_path": "/config.json"}
        assert turn["tool_io_plaintext"][0]["result"] == '{"key": "value"}'

    def test_multi_tool_turn(self):
        records = make_multi_tool_session()
        turns = extract_turns(records)
        assert len(turns) == 1
        turn = turns[0]
        assert len(turn["tool_interactions"]) == 2
        names = [ti.tool_name for ti in turn["tool_interactions"]]
        assert names == ["Read", "Write"]

    def test_no_tool_turn_has_empty_interactions(self):
        from tests.conftest import make_session_jsonl
        records = make_session_jsonl([
            ("hello", "hi there", "test-model"),
        ])
        turns = extract_turns(records)
        assert len(turns) == 1
        assert turns[0]["tool_interactions"] == []
        assert turns[0]["tool_io_plaintext"] == []
