"""Tests for the claudedeck show command and helpers."""

import json
import pytest
from unittest.mock import patch

from claudedeck.core import Chain
from claudedeck.__main__ import (
    cmd_show,
    _group_exchanges,
    _is_tool_result_only,
    _parse_tool_names,
    _clean_prompt,
)


def _make_session(tmp_path, turns, session_id="test-session"):
    """Create chain + vault files for testing.

    Args:
        turns: list of (prompt, response) tuples.
               If response starts with "[tool_use:", it's treated as a tool step.
    """
    (tmp_path / ".git").mkdir(exist_ok=True)
    deck_dir = tmp_path / ".claudedeck"
    deck_dir.mkdir(exist_ok=True)

    chain = Chain()
    vault = {}
    for i, (prompt, response) in enumerate(turns):
        chain.append_turn(prompt=prompt, response=response, model="test-model")
        vault[str(i)] = {"prompt": prompt, "response": response}

    chain.save(deck_dir / f"{session_id}.chain.jsonl")
    with open(deck_dir / f"{session_id}.vault.json", "w") as f:
        json.dump(vault, f)

    return deck_dir


class TestGroupExchanges:
    def test_single_turn(self):
        chain = Chain()
        chain.append_turn(prompt="hello", response="world", model="m")
        vault = {"0": {"prompt": "hello", "response": "world"}}

        exchanges = _group_exchanges(chain.records, vault)
        assert len(exchanges) == 1
        assert exchanges[0]["prompt"] == "hello"
        assert exchanges[0]["final_response"] == "world"
        assert exchanges[0]["tool_steps"] == []

    def test_multiple_turns(self):
        chain = Chain()
        chain.append_turn(prompt="q1", response="a1", model="m")
        chain.append_turn(prompt="q2", response="a2", model="m")
        vault = {
            "0": {"prompt": "q1", "response": "a1"},
            "1": {"prompt": "q2", "response": "a2"},
        }

        exchanges = _group_exchanges(chain.records, vault)
        assert len(exchanges) == 2
        assert exchanges[0]["prompt"] == "q1"
        assert exchanges[1]["prompt"] == "q2"

    def test_tool_use_collapsed(self):
        chain = Chain()
        chain.append_turn(prompt="do something", response="[tool_use: Read]", model="m")
        chain.append_turn(prompt="", response="[tool_use: Bash]", model="m")
        chain.append_turn(prompt="", response="Done.", model="m")
        vault = {
            "0": {"prompt": "do something", "response": "[tool_use: Read]"},
            "1": {"prompt": "", "response": "[tool_use: Bash]"},
            "2": {"prompt": "", "response": "Done."},
        }

        exchanges = _group_exchanges(chain.records, vault)
        assert len(exchanges) == 1
        assert exchanges[0]["prompt"] == "do something"
        assert exchanges[0]["final_response"] == "Done."
        assert len(exchanges[0]["tool_steps"]) == 2  # Read and Bash
        assert len(exchanges[0]["records"]) == 3

    def test_tool_result_relay_not_new_exchange(self):
        """Tool result relays (prompts that are just JSON/XML) shouldn't start new exchanges."""
        chain = Chain()
        chain.append_turn(prompt="read my file", response="[tool_use: Read]", model="m")
        chain.append_turn(prompt='{"content": "file data"}', response="Here is your file.", model="m")
        vault = {
            "0": {"prompt": "read my file", "response": "[tool_use: Read]"},
            "1": {"prompt": '{"content": "file data"}', "response": "Here is your file."},
        }

        exchanges = _group_exchanges(chain.records, vault)
        assert len(exchanges) == 1
        assert exchanges[0]["final_response"] == "Here is your file."

    def test_seq_range(self):
        chain = Chain()
        chain.append_turn(prompt="q", response="[tool_use: Bash]", model="m")
        chain.append_turn(prompt="", response="Done", model="m")
        vault = {
            "0": {"prompt": "q", "response": "[tool_use: Bash]"},
            "1": {"prompt": "", "response": "Done"},
        }

        exchanges = _group_exchanges(chain.records, vault)
        assert exchanges[0]["start_seq"] == 0
        assert exchanges[0]["records"][-1].seq == 1


class TestIsToolResultOnly:
    def test_empty_string(self):
        assert _is_tool_result_only("") is True

    def test_whitespace(self):
        assert _is_tool_result_only("   ") is True

    def test_json_object(self):
        assert _is_tool_result_only('{"tool_use_id": "x"}') is True

    def test_xml_tag(self):
        assert _is_tool_result_only("<tool_result>data</tool_result>") is True

    def test_real_prompt(self):
        assert _is_tool_result_only("Write a function") is False

    def test_prompt_with_whitespace(self):
        assert _is_tool_result_only("  hello  ") is False


class TestParseToolNames:
    def test_single_tool(self):
        assert _parse_tool_names("[tool_use: Read]") == ["Read"]

    def test_multiple_tools(self):
        result = _parse_tool_names("[tool_use: Read]\n[tool_use: Bash]")
        assert result == ["Read", "Bash"]

    def test_no_tools(self):
        assert _parse_tool_names("Just a normal response") == []


class TestCleanPrompt:
    def test_plain_text(self):
        assert _clean_prompt("hello world") == "hello world"

    def test_removes_ide_tags(self):
        prompt = "<ide_opened_file>some/file.py</ide_opened_file>\nhello"
        assert _clean_prompt(prompt) == "hello"

    def test_removes_system_reminders(self):
        prompt = "<system-reminder>stuff</system-reminder>\nhello"
        assert _clean_prompt(prompt) == "hello"

    def test_context_only(self):
        prompt = "<ide_opened_file>file.py</ide_opened_file>"
        assert _clean_prompt(prompt) == "(context-only prompt)"


class TestCmdShow:
    def test_show_basic(self, tmp_path, capsys):
        _make_session(tmp_path, [
            ("hello", "Hi there!"),
            ("how are you", "I'm doing well."),
        ])

        args = type("Args", (), {"session": "test-session", "seq": None, "verbose": False})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_show(args)

        output = capsys.readouterr().out
        assert "YOU: hello" in output
        assert "CLAUDE: Hi there!" in output
        assert "YOU: how are you" in output
        assert "Exchanges: 2" in output

    def test_show_with_tool_use(self, tmp_path, capsys):
        _make_session(tmp_path, [
            ("do something", "[tool_use: Read]"),
            ("", "[tool_use: Bash]"),
            ("", "All done."),
        ])

        args = type("Args", (), {"session": "test-session", "seq": None, "verbose": False})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_show(args)

        output = capsys.readouterr().out
        assert "TOOLS: Read, Bash" in output
        assert "CLAUDE: All done." in output
        assert "Exchanges: 1" in output

    def test_show_seq_filter(self, tmp_path, capsys):
        _make_session(tmp_path, [
            ("first", "answer one"),
            ("second", "answer two"),
        ])

        args = type("Args", (), {"session": "test-session", "seq": 0, "verbose": False})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_show(args)

        output = capsys.readouterr().out
        assert "first" in output
        assert "second" not in output

    def test_show_no_vault(self, tmp_path, capsys):
        (tmp_path / ".git").mkdir()
        deck_dir = tmp_path / ".claudedeck"
        deck_dir.mkdir()

        chain = Chain()
        chain.append_turn(prompt="hi", response="hey")
        chain.save(deck_dir / "test-session.chain.jsonl")
        # No vault file

        args = type("Args", (), {"session": "test-session", "seq": None, "verbose": False})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            with pytest.raises(SystemExit):
                cmd_show(args)

        output = capsys.readouterr().out
        assert "Vault not found" in output

    def test_show_tool_counts(self, tmp_path, capsys):
        _make_session(tmp_path, [
            ("do stuff", "[tool_use: Bash]"),
            ("", "[tool_use: Bash]"),
            ("", "[tool_use: Read]"),
            ("", "Result here."),
        ])

        args = type("Args", (), {"session": "test-session", "seq": None, "verbose": False})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_show(args)

        output = capsys.readouterr().out
        assert "Bash x2" in output
        assert "Read" in output

    def test_show_chain_validity_displayed(self, tmp_path, capsys):
        _make_session(tmp_path, [("hi", "hey")])

        args = type("Args", (), {"session": "test-session", "seq": None, "verbose": False})()
        with patch("claudedeck.__main__.find_project_root", return_value=tmp_path):
            cmd_show(args)

        output = capsys.readouterr().out
        assert "VALID" in output
