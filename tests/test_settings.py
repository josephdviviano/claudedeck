"""Tests for claudedeck.settings — hook installation and project root detection."""

import json
import pytest

from claudedeck.settings import (
    find_project_root,
    read_settings,
    write_settings,
    get_hook_command,
    is_hook_installed,
    install_hook,
    remove_hook,
    HOOK_MARKER,
)


class TestFindProjectRoot:
    def test_finds_git_dir(self, tmp_path):
        (tmp_path / ".git").mkdir()
        assert find_project_root(tmp_path) == tmp_path

    def test_claude_dir_alone_not_sufficient(self, tmp_path):
        """A bare .claude/ dir (like ~/.claude/) should NOT make a directory a project root."""
        isolated = tmp_path / "fakehome"
        isolated.mkdir()
        (isolated / ".claude").mkdir()
        with pytest.raises(FileNotFoundError):
            find_project_root(isolated)

    def test_finds_parent(self, tmp_path):
        (tmp_path / ".git").mkdir()
        child = tmp_path / "src" / "lib"
        child.mkdir(parents=True)
        assert find_project_root(child) == tmp_path

    def test_not_found_raises(self, tmp_path):
        isolated = tmp_path / "isolated"
        isolated.mkdir()
        with pytest.raises(FileNotFoundError):
            find_project_root(isolated)


class TestReadWriteSettings:
    def test_read_nonexistent(self, tmp_path):
        assert read_settings(tmp_path / "nope.json") == {}

    def test_write_and_read(self, tmp_path):
        path = tmp_path / ".claude" / "settings.local.json"
        data = {"permissions": {"allow": ["Bash(ls)"]}, "hooks": {}}
        write_settings(path, data)
        loaded = read_settings(path)
        assert loaded == data

    def test_write_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "nested" / "settings.json"
        write_settings(path, {"key": "value"})
        assert path.exists()


class TestHookInstallation:
    def test_install_fresh(self):
        settings = install_hook({})
        assert is_hook_installed(settings)
        assert HOOK_MARKER in json.dumps(settings)

    def test_install_preserves_existing(self):
        settings = {
            "permissions": {"allow": ["Bash(ls)"]},
            "hooks": {
                "Notification": [{"matcher": "", "hooks": [{"type": "command", "command": "notify"}]}],
            },
        }
        result = install_hook(settings)
        assert is_hook_installed(result)
        # Existing hooks preserved
        assert "Notification" in result["hooks"]
        assert result["permissions"] == {"allow": ["Bash(ls)"]}

    def test_install_idempotent(self):
        settings = install_hook({})
        settings2 = install_hook(settings)
        # Should not add a duplicate
        stop_hooks = settings2["hooks"]["Stop"]
        claudedeck_hooks = [
            g for g in stop_hooks
            for h in g.get("hooks", [])
            if HOOK_MARKER in h.get("command", "")
        ]
        assert len(claudedeck_hooks) == 1

    def test_not_installed_by_default(self):
        assert is_hook_installed({}) is False
        assert is_hook_installed({"hooks": {}}) is False
        assert is_hook_installed({"hooks": {"Stop": []}}) is False


class TestHookRemoval:
    def test_remove(self):
        settings = install_hook({})
        assert is_hook_installed(settings)
        settings = remove_hook(settings)
        assert is_hook_installed(settings) is False

    def test_remove_preserves_other_hooks(self):
        settings = {
            "hooks": {
                "Stop": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "other-tool"}]},
                ],
                "Notification": [{"matcher": "", "hooks": [{"type": "command", "command": "notify"}]}],
            },
        }
        settings = install_hook(settings)
        settings = remove_hook(settings)
        # Other Stop hook should remain
        assert len(settings["hooks"]["Stop"]) == 1
        assert "other-tool" in settings["hooks"]["Stop"][0]["hooks"][0]["command"]
        # Notification hook untouched
        assert "Notification" in settings["hooks"]

    def test_remove_cleans_empty_hooks(self):
        settings = install_hook({})
        settings = remove_hook(settings)
        assert "hooks" not in settings

    def test_remove_when_not_installed(self):
        settings = {"permissions": {"allow": []}}
        result = remove_hook(settings)
        assert result == settings

    def test_get_hook_command_format(self):
        cmd = get_hook_command()
        assert "python" in cmd.lower() or "Python" in cmd
        assert "claudedeck.hook" in cmd
