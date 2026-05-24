"""Signature loader for OgunScan.

Resolution order (first hit wins):

  1. Fresh remote fetch from `https://ogunscan.dev/signatures/latest.json`
     if the local cache is older than CACHE_TTL_SECONDS or missing entirely.
  2. Cached copy at `~/.ogunscan/cache/signatures.json` if the network is
     unreachable or the remote returns an error.
  3. Bundled `builtin.json` shipped inside the package — always present,
     always parseable. Last-resort floor for offline first-runs.

Pure-stdlib (urllib) so the package keeps `dependencies = []` in pyproject.

The cache is a JSON file with two top-level keys:

  {"fetched_at": "<ISO8601>", "signatures": {<the full signatures dict>}}

`fetched_at` is checked against `time.time()` to enforce TTL. The
signatures dict structure mirrors `rules/builtin.json` exactly so any
loader hands back the same shape regardless of source.
"""

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .rules import load_builtin

DEFAULT_REMOTE_URL = "https://ogunscan.dev/signatures/latest.json"
DEFAULT_CACHE_PATH = Path.home() / ".ogunscan" / "cache" / "signatures.json"
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h
FETCH_TIMEOUT_SECONDS = 10


def load_signatures(
    remote_url: str = DEFAULT_REMOTE_URL,
    cache_path: Path = DEFAULT_CACHE_PATH,
    ttl_seconds: int = CACHE_TTL_SECONDS,
    timeout: int = FETCH_TIMEOUT_SECONDS,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """Return a signatures dict using the resolution order above.

    Always returns a usable dict — never raises. Errors at any layer
    fall through to the next layer. The bundled builtin guarantees the
    function never fails.
    """
    # Cache hit (within TTL, not forced) — return cache, no network call.
    if not force_refresh:
        cached = _read_cache(cache_path)
        if cached is not None and _cache_fresh(cached, ttl_seconds):
            return cached["signatures"]

    # Try the network. On any failure, fall back to cache (even stale).
    fetched = _fetch_remote(remote_url, timeout)
    if fetched is not None:
        _write_cache(cache_path, fetched)
        return fetched

    # Stale cache is better than the bundled builtin (it was real at some point).
    cached = _read_cache(cache_path)
    if cached is not None:
        return cached["signatures"]

    # Last resort: ship-time bundled defaults.
    return load_builtin()


# ── internals ────────────────────────────────────────────────────────────


def _fetch_remote(url: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Fetch + parse remote signatures. Returns None on any error."""
    req = urllib.request.Request(url, headers={"User-Agent": "ogunscan-signatures/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = resp.read().decode("utf-8")
        data = json.loads(body)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, OSError):
        return None
    # Sanity: must have a `rules` array. Reject anything that doesn't.
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        return None
    return data


def _read_cache(cache_path: Path) -> Optional[Dict[str, Any]]:
    """Read cache file. Returns the wrapper dict (with `fetched_at` + `signatures`),
    not the signatures alone. Returns None if missing or malformed."""
    try:
        if not cache_path.exists():
            return None
        wrapper = json.loads(cache_path.read_text(encoding="utf-8"))
        if not isinstance(wrapper, dict):
            return None
        if "signatures" not in wrapper or "fetched_at" not in wrapper:
            return None
        return wrapper
    except (json.JSONDecodeError, OSError):
        return None


def _cache_fresh(wrapper: Dict[str, Any], ttl_seconds: int) -> bool:
    try:
        ts = datetime.fromisoformat(wrapper["fetched_at"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age < ttl_seconds


def _write_cache(cache_path: Path, signatures: Dict[str, Any]) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper = {
            "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "signatures": signatures,
        }
        cache_path.write_text(json.dumps(wrapper), encoding="utf-8")
    except OSError:
        # Cache write failures are non-fatal — the loader will refetch next time.
        pass
