"""
tests/test_airlock_boundaries.py — Extended signing airlock boundary tests.

The signing airlock (validate_hash_only) is the security boundary that
prevents plaintext from reaching external services. These tests probe
boundary conditions, near-misses, and injection attempts.

Existing test_signing.py covers 17 basic cases. This file adds
boundary-specific and injection-focused tests.
"""

import pytest

from claudedeck.signing import validate_hash_only
from claudedeck.core import sha256_hex


class TestAirlockBoundaryLengths:
    """Test strings that are close to the valid 64-char hex length."""

    def test_63_chars_rejected(self):
        """One character too short."""
        with pytest.raises(ValueError, match="not a valid SHA-256"):
            validate_hash_only("a" * 63)

    def test_65_chars_rejected(self):
        """One character too long."""
        with pytest.raises(ValueError, match="not a valid SHA-256"):
            validate_hash_only("a" * 65)

    def test_0_chars_rejected(self):
        """Empty string."""
        with pytest.raises(ValueError):
            validate_hash_only("")

    def test_128_chars_rejected(self):
        """Double-length (SHA-512 hex length)."""
        with pytest.raises(ValueError):
            validate_hash_only("a" * 128)

    def test_32_chars_rejected(self):
        """MD5 hex length."""
        with pytest.raises(ValueError):
            validate_hash_only("a" * 32)

    def test_exactly_64_chars_accepted(self):
        """Exactly 64 lowercase hex characters."""
        valid = "a" * 64
        assert validate_hash_only(valid) == valid


class TestAirlockWhitespaceInjection:
    """Whitespace around or within the hash should be rejected."""

    def test_trailing_newline_rejected(self):
        """Trailing \\n (Python's $ anchor would match this with re.match)."""
        with pytest.raises(ValueError):
            validate_hash_only("a" * 64 + "\n")

    def test_leading_newline_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("\n" + "a" * 64)

    def test_trailing_space_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 64 + " ")

    def test_leading_space_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only(" " + "a" * 64)

    def test_trailing_tab_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 64 + "\t")

    def test_trailing_carriage_return_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 64 + "\r")

    def test_embedded_space_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 32 + " " + "a" * 31)

    def test_embedded_newline_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 32 + "\n" + "a" * 31)


class TestAirlockCharacterRanges:
    """Only lowercase hex characters [0-9a-f] should be accepted."""

    def test_uppercase_hex_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("A" * 64)

    def test_mixed_case_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("aAbBcCdD" * 8)

    @pytest.mark.parametrize("char", list("ghijklmnopqrstuvwxyz"))
    def test_non_hex_lowercase_rejected(self, char):
        """Characters g-z are not valid hex."""
        with pytest.raises(ValueError):
            validate_hash_only(char * 64)

    @pytest.mark.parametrize("char", list("GHIJKLMNOPQRSTUVWXYZ"))
    def test_non_hex_uppercase_rejected(self, char):
        with pytest.raises(ValueError):
            validate_hash_only(char * 64)

    def test_all_valid_hex_chars_accepted(self):
        """A string using all valid hex characters passes."""
        # Use chars 0-9 and a-f
        valid = "0123456789abcdef" * 4  # 64 chars
        assert validate_hash_only(valid) == valid


class TestAirlockInjectionAttempts:
    """Attempts to smuggle non-hash data through the airlock."""

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 32 + "\x00" + "a" * 31)

    def test_json_payload_rejected(self):
        """JSON content cannot pass through."""
        with pytest.raises(ValueError):
            validate_hash_only('{"prompt":"steal this"}')

    def test_url_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("https://evil.com/exfil?data=secret")

    def test_file_path_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("/etc/passwd")

    def test_command_injection_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("; rm -rf / #" + "a" * 52)

    def test_hex_encoded_plaintext_wrong_length(self):
        """Hex-encoding short plaintext doesn't produce 64 chars."""
        plaintext = "secret"
        hex_encoded = plaintext.encode().hex()  # 12 chars
        with pytest.raises(ValueError):
            validate_hash_only(hex_encoded)

    def test_hex_encoded_plaintext_right_length_accepted(self):
        """32-byte plaintext hex-encoded IS 64 hex chars — indistinguishable.

        This is a fundamental limitation: the airlock can't tell a real
        SHA-256 hash from 32 bytes of arbitrary data encoded as hex.
        The airlock prevents ACCIDENTAL leakage, not determined attacks.
        """
        # 32 bytes of "plaintext" encoded as hex looks like a hash
        data = b"This is exactly 32 bytes long!?!"
        assert len(data) == 32
        hex_encoded = data.hex()
        # This WILL pass — it's structurally indistinguishable from a hash
        result = validate_hash_only(hex_encoded)
        assert result == hex_encoded


class TestAirlockTypeChecks:
    """Non-string types must be rejected."""

    def test_none_rejected(self):
        with pytest.raises(ValueError, match="Expected str"):
            validate_hash_only(None)

    def test_int_rejected(self):
        with pytest.raises(ValueError, match="Expected str"):
            validate_hash_only(42)

    def test_bytes_rejected(self):
        with pytest.raises(ValueError, match="Expected str"):
            validate_hash_only(b"a" * 64)

    def test_list_rejected(self):
        with pytest.raises(ValueError, match="Expected str"):
            validate_hash_only(["a" * 64])

    def test_dict_rejected(self):
        with pytest.raises(ValueError, match="Expected str"):
            validate_hash_only({"hash": "a" * 64})


class TestAirlockWithRealHashes:
    """Confirm that actual SHA-256 output passes the airlock."""

    def test_sha256_of_empty_string(self):
        h = sha256_hex(b"")
        assert validate_hash_only(h) == h

    def test_sha256_of_content(self):
        h = sha256_hex(b"claudedeck chain record")
        assert validate_hash_only(h) == h

    def test_sha256_is_always_lowercase(self):
        """sha256_hex always returns lowercase."""
        h = sha256_hex(b"test")
        assert h == h.lower()
        assert len(h) == 64
