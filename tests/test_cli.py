"""Tests for claudedeck CLI subcommands."""

import json
import pytest
from unittest.mock import patch
from pathlib import Path

from claudedeck.core import Chain
from claudedeck.settings import install_hook, write_settings, get_settings_path


class TestCLIOn:
    def test_on_creates_hook(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".claude").mkdir()

        from claudedeck.__main__ import cmd_on
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_on(None)

        settings_path = get_settings_path(tmp_path)
        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "Stop" in settings["hooks"]

        # .claudedeck/ should exist
        assert (tmp_path / ".claudedeck").is_dir()

    def test_on_idempotent(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".claude").mkdir()

        from claudedeck.__main__ import cmd_on
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_on(None)
            cmd_on(None)  # Should not error or duplicate

        settings_path = get_settings_path(tmp_path)
        settings = json.loads(settings_path.read_text())
        stop_groups = settings["hooks"]["Stop"]
        assert len(stop_groups) == 1


class TestCLIOff:
    def test_off_removes_hook(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".claude").mkdir()

        from claudedeck.__main__ import cmd_on, cmd_off
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_on(None)
            cmd_off(None)

        settings_path = get_settings_path(tmp_path)
        settings = json.loads(settings_path.read_text())
        assert "hooks" not in settings or "Stop" not in settings.get("hooks", {})


class TestCLIVerify:
    def test_verify_valid_chain(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.append_turn(prompt="foo", response="bar")
        chain.save(deck_dir / "test-session.chain.jsonl")

        from claudedeck.__main__ import cmd_verify
        args = type("Args", (), {"session": "test-session"})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_verify(args)

        output = capsys.readouterr().out
        assert "VALID" in output
        assert "2 records" in output

    def test_verify_tampered_chain(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        chain = Chain()
        chain.append_turn(prompt="hello", response="world")
        chain.save(deck_dir / "test-session.chain.jsonl")

        # Tamper with the chain file
        chain_path = deck_dir / "test-session.chain.jsonl"
        data = json.loads(chain_path.read_text().strip())
        data["record_hash"] = "f" * 64
        chain_path.write_text(json.dumps(data) + "\n")

        from claudedeck.__main__ import cmd_verify
        args = type("Args", (), {"session": "test-session"})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            with pytest.raises(SystemExit) as exc_info:
                cmd_verify(args)
            assert exc_info.value.code == 1


class TestCLIInspect:
    def test_inspect_shows_records(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        chain = Chain()
        chain.append_turn(prompt="test prompt", response="test response", model="opus")
        chain.save(deck_dir / "test-session.chain.jsonl")

        # Create vault
        vault = {"0": {"prompt": "test prompt", "response": "test response"}}
        with open(deck_dir / "test-session.vault.json", "w") as f:
            json.dump(vault, f)

        from claudedeck.__main__ import cmd_inspect
        args = type("Args", (), {"session": "test-session"})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_inspect(args)

        output = capsys.readouterr().out
        assert "seq 0" in output
        assert "test prompt" in output
        assert "opus" in output


class TestCLIStatus:
    def test_status_no_sessions(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".claude").mkdir()

        from claudedeck.__main__ import cmd_status
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_status(None)

        output = capsys.readouterr().out
        assert "DISABLED" in output

    def test_status_with_session(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".claude").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        # Create a chain
        chain = Chain()
        chain.append_turn(prompt="hi", response="hey")
        chain.save(deck_dir / "sess-001.chain.jsonl")

        # Install hook
        settings_path = get_settings_path(tmp_path)
        write_settings(settings_path, install_hook({}))

        from claudedeck.__main__ import cmd_status
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_status(None)

        output = capsys.readouterr().out
        assert "ENABLED" in output
        assert "sess-001" in output
        assert "VALID" in output
