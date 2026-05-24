"""Tests for the signatures loader.

Network calls are mocked — these tests never touch ogunscan.dev. A separate
live test (`test_signatures_live.py`) hits the real endpoint and is the
end-to-end verification for the deployed signatures file.
"""

import io
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ogunscan.signatures import load_signatures, _write_cache, _read_cache, _cache_fresh
from ogunscan.rules import load_builtin


# ── helpers ──────────────────────────────────────────────────────────────


def _mk_signatures(version: str = "test-1") -> dict:
    """Minimal valid signatures dict for tests."""
    return {
        "version": version,
        "updated_at": "2026-05-24T00:00:00Z",
        "rules": [
            {"id": "OGN-100", "severity": "HIGH", "title": "test", "description": "x", "remediation": "y"}
        ],
        "patterns": {"credentials": [], "injection": [], "suspicious_urls": [], "dangerous_permissions": []},
    }


def _fake_urlopen(payload: bytes, status: int = 200):
    """Build a fake urlopen context-manager that returns the given payload."""
    class _Resp:
        def __init__(self, p, s):
            self._p = p
            self.status = s
        def read(self):
            return self._p
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    def _fn(req, timeout=10):
        return _Resp(payload, status)
    return _fn


# ── tests ────────────────────────────────────────────────────────────────


def test_no_cache_no_network_falls_back_to_builtin():
    """First-run offline: returns the bundled builtin."""
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        with patch("ogunscan.signatures._fetch_remote", return_value=None):
            sigs = load_signatures(cache_path=cache)
        builtin = load_builtin()
        # Both have the same shape; rules count is the meaningful test.
        assert len(sigs["rules"]) == len(builtin["rules"])
        assert sigs["rules"][0]["id"] == builtin["rules"][0]["id"]


def test_fresh_cache_hits_no_network():
    """Within TTL: cache wins, network is not called."""
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        sample = _mk_signatures(version="cached-1")
        _write_cache(cache, sample)
        with patch("ogunscan.signatures._fetch_remote") as fetch:
            sigs = load_signatures(cache_path=cache)
            fetch.assert_not_called()
        assert sigs["version"] == "cached-1"


def test_stale_cache_triggers_network_fetch():
    """Past TTL: network IS called; fresh result returned and cache updated."""
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        old = _mk_signatures(version="cached-old")
        # Force-write a stale wrapper (TTL=0 means anything is stale)
        _write_cache(cache, old)
        fresh = _mk_signatures(version="fetched-new")
        with patch("ogunscan.signatures._fetch_remote", return_value=fresh) as fetch:
            sigs = load_signatures(cache_path=cache, ttl_seconds=0)
            fetch.assert_called_once()
        assert sigs["version"] == "fetched-new"
        # Cache should have been overwritten with the fresh fetch
        wrapper = _read_cache(cache)
        assert wrapper["signatures"]["version"] == "fetched-new"


def test_network_failure_falls_back_to_stale_cache():
    """When the network is down, stale cache is still better than nothing."""
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        old = _mk_signatures(version="cached-old")
        _write_cache(cache, old)
        with patch("ogunscan.signatures._fetch_remote", return_value=None):
            sigs = load_signatures(cache_path=cache, ttl_seconds=0)
        assert sigs["version"] == "cached-old"


def test_network_returns_bad_json_falls_back():
    """Malformed network response is treated as a network failure."""
    bad_payload = b"<!DOCTYPE html><html>404</html>"
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        with patch("urllib.request.urlopen", _fake_urlopen(bad_payload)):
            with patch("ogunscan.signatures._read_cache", return_value=None):
                sigs = load_signatures(cache_path=cache)
        # Should fall back to builtin
        builtin = load_builtin()
        assert len(sigs["rules"]) == len(builtin["rules"])


def test_network_returns_missing_rules_key_falls_back():
    """A 200 response with a malformed schema (no `rules` array) is rejected."""
    bad_shape = json.dumps({"version": "broken", "patterns": {}}).encode("utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        with patch("urllib.request.urlopen", _fake_urlopen(bad_shape)):
            sigs = load_signatures(cache_path=cache)
        builtin = load_builtin()
        assert sigs["rules"][0]["id"] == builtin["rules"][0]["id"]


def test_force_refresh_skips_cache():
    """force_refresh=True bypasses cache freshness check."""
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "sig.json"
        _write_cache(cache, _mk_signatures(version="cached"))
        fresh = _mk_signatures(version="forced-fresh")
        with patch("ogunscan.signatures._fetch_remote", return_value=fresh) as fetch:
            sigs = load_signatures(cache_path=cache, force_refresh=True)
            fetch.assert_called_once()
        assert sigs["version"] == "forced-fresh"


def test_cache_write_atomicity_failure_is_noisy_but_nonfatal():
    """If the cache directory can't be created (e.g. read-only fs), load_signatures
    still returns valid data — cache write is best-effort, never blocking."""
    # Point cache at a path inside a file (can't mkdir into a file). Verify
    # the loader returns useful data anyway via the network-then-builtin chain.
    with tempfile.NamedTemporaryFile() as f:
        impossible_cache = Path(f.name) / "subdir" / "sig.json"
        fresh = _mk_signatures(version="net-ok")
        with patch("ogunscan.signatures._fetch_remote", return_value=fresh):
            sigs = load_signatures(cache_path=impossible_cache)
        assert sigs["version"] == "net-ok"


def test_load_builtin_is_always_callable():
    """The bundled fallback must load without error from the package data.
    Phase 5 added 5 remote-scan rules (OGN-600..604) bringing total to 13;
    this test asserts the bundled count keeps tracking what we ship."""
    builtin = load_builtin()
    assert "rules" in builtin
    assert len(builtin["rules"]) == 13
    rule_ids = {r["id"] for r in builtin["rules"]}
    # Local-config rules (Phase 1)
    assert {"OGN-100", "OGN-101", "OGN-200", "OGN-201", "OGN-202", "OGN-300", "OGN-400", "OGN-500"}.issubset(rule_ids)
    # Remote-scan rules (Phase 5)
    assert {"OGN-600", "OGN-601", "OGN-602", "OGN-603", "OGN-604"}.issubset(rule_ids)


if __name__ == "__main__":
    tests = [
        test_no_cache_no_network_falls_back_to_builtin,
        test_fresh_cache_hits_no_network,
        test_stale_cache_triggers_network_fetch,
        test_network_failure_falls_back_to_stale_cache,
        test_network_returns_bad_json_falls_back,
        test_network_returns_missing_rules_key_falls_back,
        test_force_refresh_skips_cache,
        test_cache_write_atomicity_failure_is_noisy_but_nonfatal,
        test_load_builtin_is_always_callable,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {t.__name__}: {e}")
        except Exception as e:
            print(f"  💥 {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
