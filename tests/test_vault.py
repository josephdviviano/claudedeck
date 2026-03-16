"""Tests for claudedeck.vault — encrypted storage for session plaintext."""

import base64
import json
import os
import pytest

from cryptography.fernet import InvalidToken

from claudedeck.core import Chain, sha256_hex
from claudedeck.vault import Vault
from tests.conftest import SAMPLE_TURNS


# ---------------------------------------------------------------------------
# Create and load
# ---------------------------------------------------------------------------

class TestVaultCreateAndLoad:
    def test_new_vault_empty(self, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        assert v.list_entries() == []

    def test_store_retrieve_roundtrip(self, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        v.store(0, "prompt", "response")
        entry = v.retrieve(0)
        assert entry["prompt"] == "prompt"
        assert entry["response"] == "response"
        assert entry["artifacts"] == {}

    def test_save_reload(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "hello", "world")
        v.save()

        v2 = Vault(path, "pass")
        assert v2.retrieve(0)["prompt"] == "hello"
        assert v2.retrieve(0)["response"] == "world"

    def test_multiple_entries(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        for i, (p, r) in enumerate(SAMPLE_TURNS):
            v.store(i, p, r)
        v.save()

        v2 = Vault(path, "pass")
        assert len(v2.list_entries()) == 3
        for i, (p, r) in enumerate(SAMPLE_TURNS):
            assert v2.retrieve(i)["prompt"] == p
            assert v2.retrieve(i)["response"] == r

    def test_sorted_listing(self, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        v.store(5, "a", "b")
        v.store(1, "c", "d")
        v.store(3, "e", "f")
        assert v.list_entries() == [1, 3, 5]


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

class TestVaultEncryption:
    def test_wrong_passphrase_raises(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "correct")
        v.store(0, "secret", "data")
        v.save()

        with pytest.raises(InvalidToken):
            Vault(path, "wrong")

    def test_file_is_not_plaintext(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "secret prompt", "secret response")
        v.save()

        raw = path.read_bytes()
        assert b"secret prompt" not in raw
        assert b"secret response" not in raw

    def test_different_passphrases_different_ciphertext(self, tmp_path):
        path1 = tmp_path / "v1.vault.json"
        path2 = tmp_path / "v2.vault.json"
        for path, pw in [(path1, "alpha"), (path2, "beta")]:
            v = Vault(path, pw)
            v.store(0, "same", "content")
            v.save()

        # Ciphertext (after salt) should differ
        raw1 = path1.read_bytes()[16:]
        raw2 = path2.read_bytes()[16:]
        assert raw1 != raw2

    def test_salts_differ(self, tmp_path):
        path1 = tmp_path / "v1.vault.json"
        path2 = tmp_path / "v2.vault.json"
        for path in [path1, path2]:
            v = Vault(path, "same_pass")
            v.store(0, "x", "y")
            v.save()

        salt1 = path1.read_bytes()[:16]
        salt2 = path2.read_bytes()[:16]
        assert salt1 != salt2


# ---------------------------------------------------------------------------
# Corruption
# ---------------------------------------------------------------------------

class TestVaultCorruption:
    def test_truncated_file(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "x", "y")
        v.save()

        # Truncate to just the salt
        path.write_bytes(path.read_bytes()[:16])
        with pytest.raises(Exception):
            Vault(path, "pass")

    def test_flipped_ciphertext_byte(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "x", "y")
        v.save()

        raw = bytearray(path.read_bytes())
        # Flip a byte in the ciphertext (after 16-byte salt)
        raw[20] ^= 0xFF
        path.write_bytes(bytes(raw))
        with pytest.raises(Exception):
            Vault(path, "pass")

    def test_modified_salt(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "x", "y")
        v.save()

        raw = bytearray(path.read_bytes())
        raw[0] ^= 0xFF  # flip first salt byte
        path.write_bytes(bytes(raw))
        with pytest.raises(Exception):
            Vault(path, "pass")

    def test_empty_file(self, tmp_path):
        path = tmp_path / "v.vault.json"
        path.write_bytes(b"")
        with pytest.raises(Exception):
            Vault(path, "pass")


# ---------------------------------------------------------------------------
# Chain sync
# ---------------------------------------------------------------------------

class TestVaultChainSync:
    def test_vault_seqs_match_chain(self, chain_3turns, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        for i, (p, r) in enumerate(SAMPLE_TURNS):
            v.store(i, p, r)

        assert v.list_entries() == [rec.seq for rec in chain_3turns.records]

    def test_content_hashes_match_chain(self, chain_3turns, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        for i, (p, r) in enumerate(SAMPLE_TURNS):
            v.store(i, p, r)

        for rec in chain_3turns.records:
            entry = v.retrieve(rec.seq)
            assert sha256_hex(entry["prompt"].encode("utf-8")) == rec.turn.prompt_hash
            assert sha256_hex(entry["response"].encode("utf-8")) == rec.turn.response_hash

    def test_nonexistent_seq_returns_none(self, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        v.store(0, "a", "b")
        assert v.retrieve(99) is None


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

class TestVaultArtifacts:
    def test_store_retrieve_artifacts(self, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        arts = {"script.py": "print('hello')", "data.json": '{"key": 1}'}
        v.store(0, "prompt", "response", artifacts=arts)

        entry = v.retrieve(0)
        assert entry["artifacts"] == arts

    def test_default_empty_artifacts(self, tmp_path):
        v = Vault(tmp_path / "v.vault.json", "pass")
        v.store(0, "prompt", "response")
        assert v.retrieve(0)["artifacts"] == {}

    def test_base64_binary_content_roundtrip(self, tmp_path):
        path = tmp_path / "v.vault.json"
        binary_data = os.urandom(256)
        encoded = base64.b64encode(binary_data).decode("ascii")

        v = Vault(path, "pass")
        v.store(0, "prompt", "response", artifacts={"img.png": encoded})
        v.save()

        v2 = Vault(path, "pass")
        recovered = base64.b64decode(v2.retrieve(0)["artifacts"]["img.png"])
        assert recovered == binary_data


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestVaultEdgeCases:
    def test_unicode_content(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "Sch\u00f6ne Gr\u00fc\u00dfe \U0001f600", "\u4f60\u597d\u4e16\u754c")
        v.save()

        v2 = Vault(path, "pass")
        assert v2.retrieve(0)["prompt"] == "Sch\u00f6ne Gr\u00fc\u00dfe \U0001f600"
        assert v2.retrieve(0)["response"] == "\u4f60\u597d\u4e16\u754c"

    def test_large_payload(self, tmp_path):
        path = tmp_path / "v.vault.json"
        big = "x" * (1024 * 1024)  # 1MB
        v = Vault(path, "pass")
        v.store(0, big, big)
        v.save()

        v2 = Vault(path, "pass")
        assert len(v2.retrieve(0)["prompt"]) == 1024 * 1024

    def test_overwrite_entry(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "original", "content")
        v.store(0, "updated", "content2")
        assert v.retrieve(0)["prompt"] == "updated"

        v.save()
        v2 = Vault(path, "pass")
        assert v2.retrieve(0)["prompt"] == "updated"

    def test_empty_strings(self, tmp_path):
        path = tmp_path / "v.vault.json"
        v = Vault(path, "pass")
        v.store(0, "", "")
        v.save()

        v2 = Vault(path, "pass")
        assert v2.retrieve(0)["prompt"] == ""
        assert v2.retrieve(0)["response"] == ""
