"""
claudedeck.settings — Project settings management for hook installation.

Handles reading/writing .claude/settings.local.json and finding the
project root directory.
"""

import json
import sys
from pathlib import Path


HOOK_MARKER = "claudedeck.hook"


def find_project_root(start: Path | None = None) -> Path:
    """Walk up from start looking for a project root directory.

    Requires .git/ to be present. A bare .claude/ directory is not
    sufficient — ~/.claude/ exists on every machine with Claude Code
    installed and would incorrectly make ~ the project root.
    """
    current = (start or Path.cwd()).resolve()
    for d in [current, *current.parents]:
        if (d / ".git").exists():
            return d
    raise FileNotFoundError(
        f"No project root found (no .git/) above {current}"
    )


def get_settings_path(project_root: Path) -> Path:
    return project_root / ".claude" / "settings.local.json"


def read_settings(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def write_settings(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def get_hook_command() -> str:
    """Build the command string for the Stop hook.

    Uses `sys.executable -m claudedeck.hook` so it works whether
    claudedeck was pip-installed, editable-installed, or run from source.
    """
    python = sys.executable
    return f"{python} -m claudedeck.hook"


def is_hook_installed(settings: dict) -> bool:
    """Check if the claudedeck hook is present in settings."""
    for group in settings.get("hooks", {}).get("Stop", []):
        for hook in group.get("hooks", []):
            if HOOK_MARKER in hook.get("command", ""):
                return True
    return False


def install_hook(settings: dict) -> dict:
    """Add the claudedeck Stop hook to settings. Returns modified settings."""
    if is_hook_installed(settings):
        return settings

    command = get_hook_command()
    hook_entry = {
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": command,
            }
        ],
    }

    settings.setdefault("hooks", {})
    settings["hooks"].setdefault("Stop", [])
    settings["hooks"]["Stop"].append(hook_entry)
    return settings


def remove_hook(settings: dict) -> dict:
    """Remove the claudedeck Stop hook from settings. Returns modified settings."""
    stop_hooks = settings.get("hooks", {}).get("Stop", [])
    if not stop_hooks:
        return settings

    filtered = []
    for group in stop_hooks:
        group_hooks = [
            h for h in group.get("hooks", [])
            if HOOK_MARKER not in h.get("command", "")
        ]
        if group_hooks:
            group = {**group, "hooks": group_hooks}
            filtered.append(group)

    if filtered:
        settings["hooks"]["Stop"] = filtered
    else:
        settings.get("hooks", {}).pop("Stop", None)

    # Clean up empty hooks dict
    if not settings.get("hooks"):
        settings.pop("hooks", None)

    return settings
