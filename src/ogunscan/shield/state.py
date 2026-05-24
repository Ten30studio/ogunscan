"""Shield state — what's registered, when we last scanned, what we found.

Persisted at `~/.ogunscan/shield/state.json`. Writes are atomic (temp file
+ os.replace) so a crashed mid-write never leaves a corrupt state file.

State shape:

  {
    "schema_version": 1,
    "registered_paths": ["/abs/path/to/mcp.json", ...],
    "last_scan_at":    "2026-05-24T03:50:00Z" | null,
    "next_scan_at":    "2026-05-24T09:50:00Z" | null,
    "findings_by_path": {
      "/abs/path/to/mcp.json": [
        {"rule_id": "OGN-200", "severity": "CRITICAL", "title": "...",
         "description": "...", "location": "...", "remediation": "...",
         "evidence": "..."},
        ...
      ]
    },
    "scan_count": 0
  }
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Finding, Severity
from .paths import ensure_dirs, state_file

SCHEMA_VERSION = 2  # v2 adds registered_remotes + findings_by_remote (Phase 5)
SUPPORTED_SCHEMAS = {1, 2}


def empty_state() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "registered_paths": [],
        "registered_remotes": [],  # [{"url": "...", "name": "..."}]
        "last_scan_at": None,
        "next_scan_at": None,
        "findings_by_path": {},
        "findings_by_remote": {},  # keyed by url
        "scan_count": 0,
    }


def load_state(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read state. Auto-migrates v1 → v2. Returns empty_state() if file
    missing, unreadable, or schema unrecognised."""
    p = path or state_file()
    try:
        if not p.exists():
            return empty_state()
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return empty_state()
        sv = data.get("schema_version")
        if sv not in SUPPORTED_SCHEMAS:
            return empty_state()
        # Merge into v2 shape — adds the new fields (registered_remotes,
        # findings_by_remote) without dropping anything the existing
        # state has. This is the auto-migration path for v1 -> v2.
        merged = empty_state()
        merged.update(data)
        merged["schema_version"] = SCHEMA_VERSION
        return merged
    except (json.JSONDecodeError, OSError):
        return empty_state()


def save_state(state: Dict[str, Any], path: Optional[Path] = None) -> None:
    """Atomic write. Crashes mid-write leave the previous state intact."""
    p = path or state_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Write to a sibling temp file in the same directory (same filesystem
    # → os.replace is atomic on POSIX).
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(p.parent), prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, p)
    except Exception:
        # Best-effort cleanup of the temp; re-raise to caller
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def register_path(state: Dict[str, Any], abs_path: str) -> bool:
    """Add a path to registered_paths. Returns True if newly added, False if
    already present. Mutates `state` in place; caller saves."""
    paths = state.setdefault("registered_paths", [])
    if abs_path in paths:
        return False
    paths.append(abs_path)
    paths.sort()
    return True


def unregister_path(state: Dict[str, Any], abs_path: str) -> bool:
    """Remove a path. Returns True if it was present, False otherwise."""
    paths = state.setdefault("registered_paths", [])
    if abs_path not in paths:
        return False
    paths.remove(abs_path)
    # Also drop any cached findings for this path so a re-register starts fresh
    state.get("findings_by_path", {}).pop(abs_path, None)
    return True


def get_findings(state: Dict[str, Any], abs_path: str) -> List[Finding]:
    """Reconstruct Finding objects for one path. Returns [] if no record."""
    serialized = state.get("findings_by_path", {}).get(abs_path, [])
    return [_finding_from_dict(d) for d in serialized]


def set_findings(state: Dict[str, Any], abs_path: str, findings: Iterable[Finding]) -> None:
    """Replace stored findings for one path."""
    bucket = state.setdefault("findings_by_path", {})
    bucket[abs_path] = [_finding_to_dict(f) for f in findings]


# ── remote endpoint API (Phase 5) ────────────────────────────────────────


def register_remote(state: Dict[str, Any], url: str, name: str) -> bool:
    """Add a remote endpoint. Returns True if newly added, False if the
    URL was already registered. Updates the friendly name if the URL was
    already present with a different name."""
    remotes = state.setdefault("registered_remotes", [])
    for r in remotes:
        if r.get("url") == url:
            if r.get("name") != name:
                r["name"] = name
            return False
    remotes.append({"url": url, "name": name})
    remotes.sort(key=lambda r: r.get("url", ""))
    return True


def unregister_remote(state: Dict[str, Any], url: str) -> bool:
    remotes = state.setdefault("registered_remotes", [])
    before = len(remotes)
    state["registered_remotes"] = [r for r in remotes if r.get("url") != url]
    state.get("findings_by_remote", {}).pop(url, None)
    return len(state["registered_remotes"]) < before


def get_remote_findings(state: Dict[str, Any], url: str) -> List[Finding]:
    serialized = state.get("findings_by_remote", {}).get(url, [])
    return [_finding_from_dict(d) for d in serialized]


def set_remote_findings(state: Dict[str, Any], url: str, findings: Iterable[Finding]) -> None:
    bucket = state.setdefault("findings_by_remote", {})
    bucket[url] = [_finding_to_dict(f) for f in findings]


def mark_scan_complete(state: Dict[str, Any], at: datetime, next_at: datetime) -> None:
    state["last_scan_at"] = _iso(at)
    state["next_scan_at"] = _iso(next_at)
    state["scan_count"] = int(state.get("scan_count", 0)) + 1


# ── helpers ──────────────────────────────────────────────────────────────


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "location": f.location,
        "remediation": f.remediation,
        "evidence": f.evidence,
    }


def _finding_from_dict(d: Dict[str, Any]) -> Finding:
    return Finding(
        rule_id=d["rule_id"],
        severity=Severity(d["severity"]),
        title=d["title"],
        description=d["description"],
        location=d["location"],
        remediation=d["remediation"],
        evidence=d.get("evidence"),
    )


def initialize_if_needed() -> Dict[str, Any]:
    """Convenience for daemon startup: ensure dirs exist + load (or create) state."""
    ensure_dirs()
    return load_state()
