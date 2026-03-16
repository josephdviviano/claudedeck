"""
tests/test_canonical_edge_cases.py — canonical_json edge cases and
verify_proof.py synchronization tests.

canonical_json() is the foundation of all hashing. If it produces
different output for semantically identical input, chains break.
If core.py and verify_proof.py diverge, bundles verify differently
depending on which code runs.

Audit refs: M3 (unicode normalization), M7 (hash logic divergence)
"""

import importlib.util
import json
import unicodedata
from pathlib import Path

import pytest

from claudedeck.core import sha256_hex, canonical_json


# ---------------------------------------------------------------------------
# Load verify_proof.py as a module for comparison
# ---------------------------------------------------------------------------

def _load_verify_proof():
    """Import verify_proof.py as a module (it lives at project root)."""
    root = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location(
        "verify_proof", root / "verify_proof.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# canonical_json determinism
# ---------------------------------------------------------------------------

class TestCanonicalJsonDeterminism:
    """canonical_json must produce identical output for identical input,
    regardless of key insertion order or other Python dict quirks."""

    def test_key_ordering(self):
        """Keys are sorted regardless of insertion order."""
        d1 = {"z": 1, "a": 2, "m": 3}
        d2 = {"a": 2, "m": 3, "z": 1}
        assert canonical_json(d1) == canonical_json(d2)

    def test_nested_key_ordering(self):
        """Nested object keys are also sorted."""
        d1 = {"outer": {"z": 1, "a": 2}}
        d2 = {"outer": {"a": 2, "z": 1}}
        assert canonical_json(d1) == canonical_json(d2)

    def test_no_whitespace(self):
        """Output contains no spaces or newlines."""
        result = canonical_json({"key": "value", "list": [1, 2, 3]})
        decoded = result.decode("utf-8")
        assert " " not in decoded
        assert "\n" not in decoded
        assert "\t" not in decoded

    def test_ensure_ascii(self):
        """Non-ASCII characters are escaped."""
        result = canonical_json({"text": "caf\u00e9"})
        decoded = result.decode("utf-8")
        # ensure_ascii=True means \u00e9, not the raw byte
        assert "\\u00e9" in decoded

    def test_list_order_preserved(self):
        """Lists maintain their order (not sorted like keys)."""
        d = {"items": [3, 1, 2]}
        result = json.loads(canonical_json(d).decode("utf-8"))
        assert result["items"] == [3, 1, 2]


# ---------------------------------------------------------------------------
# Unicode normalization (M3)
# ---------------------------------------------------------------------------

class TestUnicodeNormalization:
    """Unicode allows multiple byte representations of the same
    visual character. canonical_json does NOT normalize these."""

    def test_nfc_vs_nfd_produce_same_hashes(self):
        """FIXED: canonical_json NFC-normalizes, so NFC and NFD hash identically.

        The character e-acute can be:
          NFC: U+00E9 (single codepoint)
          NFD: U+0065 U+0301 (e + combining accent)

        Both render identically and now hash identically because
        canonical_json normalizes to NFC before serialization.
        """
        text_nfc = "caf\u00e9"
        text_nfd = unicodedata.normalize("NFD", text_nfc)

        assert text_nfc != text_nfd  # Different Python representations

        h1 = sha256_hex(canonical_json({"text": text_nfc}))
        h2 = sha256_hex(canonical_json({"text": text_nfd}))

        assert h1 == h2, "NFC and NFD forms now produce identical hashes"

    def test_ensure_ascii_normalizes_both_forms(self):
        """After NFC normalization, both forms produce identical output."""
        nfc = "caf\u00e9"
        nfd = unicodedata.normalize("NFD", nfc)

        j1 = canonical_json({"t": nfc}).decode("utf-8")
        j2 = canonical_json({"t": nfd}).decode("utf-8")

        # Both should be NFC-normalized to \u00e9
        assert "\\u00e9" in j1
        assert "\\u00e9" in j2
        assert j1 == j2


# ---------------------------------------------------------------------------
# Special values and edge cases
# ---------------------------------------------------------------------------

class TestCanonicalJsonEdgeCases:

    def test_null_value(self):
        """None serializes as null."""
        result = canonical_json({"key": None})
        assert b"null" in result

    def test_boolean_values(self):
        """Booleans serialize as true/false (not True/False)."""
        result = canonical_json({"a": True, "b": False}).decode("utf-8")
        assert "true" in result
        assert "false" in result

    def test_integer_values(self):
        """Integers serialize without decimal point."""
        result = canonical_json({"n": 42}).decode("utf-8")
        assert '"n":42' in result

    def test_float_precision(self):
        """Float representation is consistent."""
        # 0.1 + 0.2 != 0.3 in IEEE 754
        val = 0.1 + 0.2
        result = canonical_json({"v": val}).decode("utf-8")
        # Should serialize the actual float value
        parsed = json.loads(result)
        assert parsed["v"] == val

    def test_empty_dict(self):
        result = canonical_json({})
        assert result == b"{}"

    def test_empty_string_value(self):
        result = canonical_json({"k": ""})
        assert result == b'{"k":""}'

    def test_empty_list_value(self):
        result = canonical_json({"k": []})
        assert result == b'{"k":[]}'

    def test_nested_empty_structures(self):
        result = canonical_json({"a": {}, "b": [], "c": ""})
        expected = b'{"a":{},"b":[],"c":""}'
        assert result == expected

    def test_control_characters_escaped(self):
        """Control characters in strings must be escaped."""
        text_with_controls = "line1\nline2\ttab\rreturn"
        result = canonical_json({"t": text_with_controls}).decode("utf-8")
        # json.dumps escapes these
        assert "\\n" in result
        assert "\\t" in result
        assert "\\r" in result

    def test_backslash_escaping(self):
        """Backslashes are properly escaped."""
        result = canonical_json({"path": "C:\\Users\\file"}).decode("utf-8")
        assert "C:\\\\Users\\\\file" in result

    def test_quote_escaping(self):
        """Quotes in strings are escaped."""
        result = canonical_json({"say": 'He said "hello"'}).decode("utf-8")
        assert '\\"hello\\"' in result

    def test_deeply_nested_structure(self):
        """Deeply nested structures serialize correctly."""
        d = {"level": 0}
        current = d
        for i in range(1, 50):
            current["child"] = {"level": i}
            current = current["child"]

        result = canonical_json(d)
        parsed = json.loads(result)
        # Walk down to verify depth
        node = parsed
        for i in range(50):
            assert node["level"] == i
            if i < 49:
                node = node["child"]

    def test_large_integer(self):
        """Very large integers serialize correctly."""
        big = 2**53 + 1  # Beyond JS safe integer range
        result = canonical_json({"n": big})
        parsed = json.loads(result)
        assert parsed["n"] == big

    def test_negative_numbers(self):
        result = canonical_json({"n": -42, "f": -3.14})
        parsed = json.loads(result)
        assert parsed["n"] == -42
        assert parsed["f"] == -3.14

    def test_mixed_type_list(self):
        """Lists with mixed types serialize correctly."""
        result = canonical_json({"items": [1, "two", True, None, 3.14]})
        parsed = json.loads(result)
        assert parsed["items"] == [1, "two", True, None, 3.14]


# ---------------------------------------------------------------------------
# verify_proof.py synchronization (M7)
# ---------------------------------------------------------------------------

class TestVerifyProofSync:
    """verify_proof.py deliberately duplicates sha256_hex and
    canonical_json from core.py. These must stay in sync."""

    @pytest.fixture
    def vp(self):
        return _load_verify_proof()

    def test_sha256_hex_matches(self, vp):
        """Both implementations produce identical SHA-256 output."""
        test_inputs = [
            b"",
            b"hello world",
            b"\x00\xff" * 100,
            "unicode café".encode("utf-8"),
        ]
        for data in test_inputs:
            assert sha256_hex(data) == vp.sha256_hex(data), (
                f"sha256_hex divergence for input {data[:20]!r}"
            )

    def test_canonical_json_matches(self, vp):
        """Both implementations produce identical canonical JSON."""
        test_objects = [
            {"z": 1, "a": 2},
            {"nested": {"y": 1, "x": 2}},
            {"list": [3, 1, 2]},
            {"empty": {}, "null": None, "bool": True},
            {"unicode": "caf\u00e9"},
            {"special": "line\nnew\ttab"},
            {},
        ]
        for obj in test_objects:
            core_result = canonical_json(obj)
            vp_result = vp.canonical_json(obj)
            assert core_result == vp_result, (
                f"canonical_json divergence for {obj}: "
                f"core={core_result!r}, vp={vp_result!r}"
            )

    def test_hash_of_chain_record_matches(self, vp):
        """A full chain record hashes identically in both implementations."""
        from claudedeck.core import Chain

        chain = Chain()
        chain.append_turn(prompt="test prompt", response="test response")

        rec_dict = chain.records[0].to_dict()
        hashable = {
            "seq": rec_dict["seq"],
            "nonce": rec_dict["nonce"],
            "turn": rec_dict["turn"],
            "timestamp": rec_dict["timestamp"],
            "prev_hash": rec_dict["prev_hash"],
        }
        if "chain_id" in rec_dict:
            hashable["chain_id"] = rec_dict["chain_id"]

        core_hash = sha256_hex(canonical_json(hashable))
        vp_hash = vp.sha256_hex(vp.canonical_json(hashable))

        assert core_hash == vp_hash
        assert core_hash == rec_dict["record_hash"]
