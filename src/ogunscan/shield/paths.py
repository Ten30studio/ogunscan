"""Filesystem paths Shield owns. Centralised so tests can monkeypatch
SHIELD_HOME and every other path follows."""

import os
from pathlib import Path


def shield_home() -> Path:
    """Root of Shield's state tree.

    Honours `OGUNSCAN_SHIELD_HOME` env override so tests + advanced users
    can relocate state without symlink games. Default: `~/.ogunscan/shield/`.
    """
    override = os.environ.get("OGUNSCAN_SHIELD_HOME")
    if override:
        return Path(override)
    return Path.home() / ".ogunscan" / "shield"


def state_file() -> Path:
    return shield_home() / "state.json"


def history_dir() -> Path:
    return shield_home() / "history"


def logs_dir() -> Path:
    return shield_home() / "logs"


def pid_file() -> Path:
    return shield_home() / "daemon.pid"


def license_file() -> Path:
    return shield_home() / "license.key"


def ensure_dirs() -> None:
    """Create the directory tree if missing. Safe to call repeatedly."""
    for d in (shield_home(), history_dir(), logs_dir()):
        d.mkdir(parents=True, exist_ok=True)
