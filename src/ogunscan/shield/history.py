"""Shield event history — append-only JSONL per UTC date.

Files at `~/.ogunscan/shield/history/YYYY-MM-DD.jsonl`. One event per line.
Used by `ogunscan shield logs` to show recent activity.

Event shape:

  {"ts": "ISO8601",
   "kind": "scan_started" | "scan_completed" | "new_finding" | "resolved_finding" | "daemon_started" | "daemon_stopped" | "error",
   ...kind-specific fields}
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .paths import ensure_dirs, history_dir


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _today_path() -> Path:
    return history_dir() / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"


def record(kind: str, **fields: Any) -> None:
    """Append a single event to today's history file. Best-effort: write
    failures are silently swallowed so they never crash the daemon —
    history is observability, not source of truth."""
    try:
        ensure_dirs()
        ev = {"ts": _now_iso(), "kind": kind, **fields}
        path = _today_path()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, sort_keys=True) + "\n")
    except OSError:
        # History is observational. The daemon must keep running even if disk is full.
        pass


def tail(n: int = 20) -> List[Dict[str, Any]]:
    """Return the last `n` events across all history files, newest last.

    Reads at most the last 3 daily files — enough for any reasonable tail.
    """
    ensure_dirs()
    files = sorted(history_dir().glob("*.jsonl"))[-3:]
    events: List[Dict[str, Any]] = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return events[-n:] if n > 0 else events


def iter_events() -> Iterator[Dict[str, Any]]:
    """Stream all history events in chronological order. Used by tests."""
    ensure_dirs()
    for f in sorted(history_dir().glob("*.jsonl")):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
