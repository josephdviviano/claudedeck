"""Tests for claudedeck.signing — the hash-only signing airlock."""

import pytest
from unittest.mock import patch

from claudedeck.signing import (
    validate_hash_only,
    sign_with_sigstore,
    stamp_with_ots,
)


VALID_HASH = "a" * 64  # valid SHA-256 hex


class TestValidateHashOnly:
    """The airlock is the critical security boundary.
    These tests ensure ONLY valid SHA-256 hex digests pass through."""

    def test_valid_hash_passes(self):
        result = validate_hash_only(VALID_HASH)
        assert result == VALID_HASH

    def test_real_sha256_passes(self):
        import hashlib
        h = hashlib.sha256(b"test data").hexdigest()
        assert validate_hash_only(h) == h

    def test_uppercase_hex_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("A" * 64)

    def test_mixed_case_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("aA" * 32)

    def test_too_short_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 63)

    def test_too_long_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 65)

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("")

    def test_plaintext_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("This is a secret prompt that should never leave the machine!")

    def test_json_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only('{"prompt": "hello", "response": "world"}')

    def test_hash_with_spaces_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only(" " + "a" * 64)

    def test_hash_with_newline_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("a" * 64 + "\n")

    def test_non_hex_chars_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("g" * 64)  # 'g' is not hex

    def test_non_string_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only(12345)

    def test_bytes_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only(b"a" * 64)

    def test_none_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only(None)

    def test_url_rejected(self):
        """URLs should never pass through the airlock."""
        with pytest.raises(ValueError):
            validate_hash_only("https://example.com/secret-data?token=abc123def456")

    def test_path_rejected(self):
        with pytest.raises(ValueError):
            validate_hash_only("/Users/researcher/secret_data/prompts.jsonl")


class TestSigstoreIntegration:
    def test_plaintext_never_reaches_subprocess(self):
        """Plaintext should be rejected BEFORE any subprocess call."""
        with patch("claudedeck.signing.subprocess.run") as mock_run:
            with pytest.raises(ValueError):
                sign_with_sigstore("This is plaintext, not a hash!")
            mock_run.assert_not_called()

    def test_valid_hash_would_call_cosign(self):
        """With cosign available, a valid hash should attempt signing."""
        with patch("claudedeck.signing.shutil.which", return_value="/usr/local/bin/cosign"):
            with patch("claudedeck.signing.subprocess.run") as mock_run:
                mock_run.return_value = type("R", (), {"returncode": 0, "stderr": ""})()
                result = sign_with_sigstore(VALID_HASH)
                assert result.success is True
                # Verify the subprocess was called
                mock_run.assert_called_once()

    def test_cosign_not_found(self):
        with patch("claudedeck.signing.shutil.which", return_value=None):
            result = sign_with_sigstore(VALID_HASH)
            assert result.success is False
            assert "not found" in result.error


class TestOTSIntegration:
    def test_plaintext_never_reaches_subprocess(self):
        with patch("claudedeck.signing.subprocess.run") as mock_run:
            with pytest.raises(ValueError):
                stamp_with_ots("secret prompt content here!")
            mock_run.assert_not_called()

    def test_ots_not_found(self):
        with patch("claudedeck.signing.shutil.which", return_value=None):
            result = stamp_with_ots(VALID_HASH)
            assert result.success is False
            assert "not found" in result.error
