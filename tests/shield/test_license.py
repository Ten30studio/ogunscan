"""Tests for the license gate — verify flow, 24h cache, offline tolerance."""

import json
import os
import sys
import tempfile
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.shield import license as L


def _scratch_shield_home():
    tmp = tempfile.TemporaryDirectory()
    os.environ["OGUNSCAN_SHIELD_HOME"] = tmp.name
    os.environ["OGUNSCAN_PRODUCT_ID"] = "test_product_id_xxx=="
    return tmp


def _clear_env():
    for k in ("OGUNSCAN_SHIELD_HOME", "OGUNSCAN_PRODUCT_ID"):
        os.environ.pop(k, None)


def _fake_verify_ok(product_id, license_key, **kw):
    return {"success": True, "uses": 1, "purchase": {"email": "buyer@example.com", "sale_id": "abc123"}}


def _fake_verify_invalid(product_id, license_key, **kw):
    return {"success": False, "message": "Sorry, that license key is invalid."}


def _fake_verify_network_error(product_id, license_key, **kw):
    return None


def test_missing_license_returns_missing_status():
    with _scratch_shield_home():
        status = L.verify_license()
        assert not status.valid
        assert status.source == "missing"
        assert "activate" in status.message
    _clear_env()


def test_no_product_id_returns_clear_error():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["OGUNSCAN_SHIELD_HOME"] = tmp
        os.environ.pop("OGUNSCAN_PRODUCT_ID", None)
        L.write_license_key("KEY-1234")
        status = L.verify_license()
        assert not status.valid
        assert status.source == "no_product_id"
    _clear_env()


def test_valid_key_writes_cache_and_returns_remote_status():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok):
            status = L.verify_license()
        assert status.valid
        assert status.source == "remote"
        assert status.purchase["email"] == "buyer@example.com"
        # Cache was written
        assert L.license_cache_path().exists()
        cached = json.loads(L.license_cache_path().read_text())
        assert cached["license_key"] == "KEY-1234"
    _clear_env()


def test_fresh_cache_hits_without_network():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok):
            L.verify_license()  # warm the cache
        # Now patch network to fail — cache should still serve
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_network_error) as f:
            status = L.verify_license()
            f.assert_not_called()
        assert status.valid
        assert status.source == "cache"
    _clear_env()


def test_force_refresh_skips_cache():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok):
            L.verify_license()  # warm cache
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok) as f:
            status = L.verify_license(force_refresh=True)
            f.assert_called_once()
        assert status.source == "remote"
    _clear_env()


def test_invalid_key_returns_invalid_status_and_does_not_cache():
    with _scratch_shield_home():
        L.write_license_key("BAD-KEY")
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_invalid):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "invalid"
        assert "invalid" in status.message.lower()
        # Cache must NOT have been written for an invalid key
        assert not L.license_cache_path().exists()
    _clear_env()


def test_network_error_falls_back_to_stale_cache():
    """Customer paid — Gumroad downtime should not lock them out of their daemon."""
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        # Warm cache
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok):
            L.verify_license()
        # Make cache "stale" by passing ttl=0; network now fails
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_network_error):
            status = L.verify_license(ttl_seconds=0)
        assert status.valid
        assert status.source == "stale_cache"
    _clear_env()


def test_network_error_and_no_cache_fails_clearly():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_network_error):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "network_error"
        assert "internet" in status.message.lower()
    _clear_env()


def test_explicit_license_key_overrides_file():
    with _scratch_shield_home():
        L.write_license_key("KEY-FROM-FILE")
        with patch("ogunscan.shield.license._fetch_verify") as f:
            f.side_effect = lambda pid, key, **kw: (
                {"success": True, "purchase": {}} if key == "KEY-EXPLICIT" else {"success": False, "message": "wrong"}
            )
            status = L.verify_license(license_key="KEY-EXPLICIT")
        assert status.valid
    _clear_env()


def test_clear_license_removes_files():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok):
            L.verify_license()
        assert L.license_cache_path().exists()
        L.clear_license()
        assert not L.license_cache_path().exists()
        assert L.read_license_key() is None
    _clear_env()


def test_read_license_key_handles_missing_file():
    with _scratch_shield_home():
        assert L.read_license_key() is None
    _clear_env()


def test_write_license_key_chmods_600():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        mode = oct(os.stat(L.license_file()).st_mode)[-3:]
        # macOS / Linux should both give 600
        assert mode == "600", f"Expected 600, got {mode}"
    _clear_env()


def test_cache_freshness_check():
    from datetime import datetime, timezone, timedelta
    # Helper: a wrapper with verified_at = N seconds ago
    def w(seconds_ago):
        ts = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat().replace("+00:00", "Z")
        return {"verified_at": ts}
    assert L._cache_fresh(w(60), ttl_seconds=120)
    assert not L._cache_fresh(w(120), ttl_seconds=60)
    assert not L._cache_fresh({}, ttl_seconds=120)


def test_invalid_cache_json_treated_as_missing():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        # Write garbage to cache
        L.license_cache_path().parent.mkdir(parents=True, exist_ok=True)
        L.license_cache_path().write_text("this is not json")
        # Should still verify via network
        with patch("ogunscan.shield.license._fetch_verify", side_effect=_fake_verify_ok) as f:
            status = L.verify_license()
            f.assert_called_once()
        assert status.valid
    _clear_env()


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {t.__name__}: {e}")
        except Exception as e:
            import traceback
            print(f"  💥 {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
