"""
tests/test_integrity.py — Tests for HMAC-based integrity checking.
"""

import json
from pathlib import Path

import pytest

from claudedeck.integrity import (
    compute_hmac, verify_hmac, hmac_json, verify_hmac_json,
)
from claudedeck.local_anchor import _load_or_create_key


class TestHMACRoundTrip:

    def test_compute_and_verify(self, tmp_path):
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        _load_or_create_key(deck_dir)  # Ensure key exists

        data = b"test data"
        mac = compute_hmac(data, deck_dir)
        assert verify_hmac(data, mac, deck_dir)

    def test_wrong_data_fails(self, tmp_path):
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        _load_or_create_key(deck_dir)

        mac = compute_hmac(b"original", deck_dir)
        assert not verify_hmac(b"tampered", mac, deck_dir)

    def test_wrong_hmac_fails(self, tmp_path):
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        _load_or_create_key(deck_dir)

        data = b"test"
        assert not verify_hmac(data, "f" * 64, deck_dir)


class TestHMACJson:

    def test_roundtrip(self, tmp_path):
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        _load_or_create_key(deck_dir)

        obj = {"chained_count": 5, "data": "test"}
        mac = hmac_json(obj, deck_dir)
        assert verify_hmac_json(obj, mac, deck_dir)

    def test_key_order_doesnt_matter(self, tmp_path):
        """canonical_json sorts keys, so insertion order is irrelevant."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        _load_or_create_key(deck_dir)

        obj1 = {"b": 2, "a": 1}
        obj2 = {"a": 1, "b": 2}

        mac1 = hmac_json(obj1, deck_dir)
        mac2 = hmac_json(obj2, deck_dir)
        assert mac1 == mac2

    def test_modified_value_fails(self, tmp_path):
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        _load_or_create_key(deck_dir)

        obj = {"count": 5}
        mac = hmac_json(obj, deck_dir)

        obj["count"] = 0  # Tamper
        assert not verify_hmac_json(obj, mac, deck_dir)

    def test_missing_key_returns_false(self, tmp_path):
        """verify_hmac returns False when key file doesn't exist."""
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()
        # Don't create the key file

        # compute_hmac will auto-create the key, so test verify directly
        assert not verify_hmac(b"test", "f" * 64, tmp_path / "nonexistent")

    def test_different_keys_produce_different_hmacs(self, tmp_path):
        """Two deck_dirs with different keys produce different HMACs."""
        dir1 = tmp_path / "deck1" / ".claudedeck"
        dir2 = tmp_path / "deck2" / ".claudedeck"
        dir1.mkdir(parents=True)
        dir2.mkdir(parents=True)
        _load_or_create_key(dir1)
        _load_or_create_key(dir2)

        data = b"same data"
        mac1 = compute_hmac(data, dir1)
        mac2 = compute_hmac(data, dir2)
        assert mac1 != mac2
