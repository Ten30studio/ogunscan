"""Tests for the license gate — Lemon Squeezy validate/activate flow, 24h
cache, offline tolerance, product matching."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.shield import license as L


def _scratch_shield_home():
    tmp = tempfile.TemporaryDirectory()
    os.environ["OGUNSCAN_SHIELD_HOME"] = tmp.name
    os.environ["OGUNSCAN_PRODUCT_ID"] = "1086399"
    return tmp


def _clear_env():
    for k in ("OGUNSCAN_SHIELD_HOME", "OGUNSCAN_PRODUCT_ID"):
        os.environ.pop(k, None)


# ── fake Lemon Squeezy responses ───────────────────────────────────────────


def _ls_valid(status="active", product_id=1086399):
    return {
        "valid": True,
        "error": None,
        "license_key": {"id": 1, "status": status, "key": "KEY-1234",
                        "activation_limit": 1, "activation_usage": 1,
                        "created_at": "2026-05-01T00:00:00Z", "expires_at": None},
        "instance": {"id": "inst-abc", "name": "san-siro", "created_at": "2026-05-01T00:00:00Z"},
        "meta": {"store_id": 386928, "product_id": product_id,
                 "product_name": "OgunScan Shield",
                 "customer_email": "buyer@example.com", "customer_name": "Jane Buyer"},
    }


def _fake_validate_ok(key, instance_id, **kw):
    return _ls_valid()


def _fake_validate_invalid(key, instance_id, **kw):
    return {"valid": False, "error": "license_key not found.", "license_key": None, "meta": None}


def _fake_validate_network_error(key, instance_id, **kw):
    return None


def _fake_activate_ok(key, instance_name, **kw):
    return _ls_valid()


# ── activation ──────────────────────────────────────────────────────────────


def test_activate_stores_key_instance_and_warms_cache():
    with _scratch_shield_home():
        with patch("ogunscan.shield.license._fetch_activate", side_effect=_fake_activate_ok):
            status = L.activate_license("KEY-1234")
        assert status.valid
        assert status.source == "remote"
        assert L.read_license_key() == "KEY-1234"
        assert L.read_instance_id() == "inst-abc"
        assert L.license_cache_path().exists()
        assert status.purchase["email"] == "buyer@example.com"
    _clear_env()


def test_activate_rejects_invalid_key():
    with _scratch_shield_home():
        with patch("ogunscan.shield.license._fetch_activate",
                   side_effect=lambda k, n, **kw: {"valid": False, "error": "no activations left."}):
            status = L.activate_license("BAD-KEY")
        assert not status.valid
        assert status.source == "invalid"
        assert L.read_license_key() is None
    _clear_env()


def test_activate_network_error_is_clear():
    with _scratch_shield_home():
        with patch("ogunscan.shield.license._fetch_activate", side_effect=lambda k, n, **kw: None):
            status = L.activate_license("KEY-1234")
        assert not status.valid
        assert status.source == "network_error"
        assert L.read_license_key() is None
    _clear_env()


# ── validation ────────────────────────────────────────────────────────────


def test_missing_license_returns_missing_status():
    with _scratch_shield_home():
        status = L.verify_license()
        assert not status.valid
        assert status.source == "missing"
        assert "activate" in status.message
    _clear_env()


def test_valid_key_writes_cache_and_returns_remote_status():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok):
            status = L.verify_license()
        assert status.valid
        assert status.source == "remote"
        assert status.purchase["email"] == "buyer@example.com"
        assert L.license_cache_path().exists()
        cached = json.loads(L.license_cache_path().read_text())
        assert cached["license_key"] == "KEY-1234"
    _clear_env()


def test_fresh_cache_hits_without_network():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok):
            L.verify_license()  # warm the cache
        with patch("ogunscan.shield.license._fetch_validate",
                   side_effect=_fake_validate_network_error) as f:
            status = L.verify_license()
            f.assert_not_called()
        assert status.valid
        assert status.source == "cache"
    _clear_env()


def test_force_refresh_skips_cache():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok):
            L.verify_license()  # warm cache
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok) as f:
            status = L.verify_license(force_refresh=True)
            f.assert_called_once()
        assert status.source == "remote"
    _clear_env()


def test_invalid_key_returns_invalid_status_and_does_not_cache():
    with _scratch_shield_home():
        L.write_license_key("BAD-KEY")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_invalid):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "invalid"
        assert not L.license_cache_path().exists()
    _clear_env()


def test_expired_status_is_rejected():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate",
                   side_effect=lambda k, i, **kw: _ls_valid(status="expired")):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "invalid"
        assert "expired" in status.message.lower()
    _clear_env()


def test_disabled_status_is_rejected():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate",
                   side_effect=lambda k, i, **kw: _ls_valid(status="disabled")):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "invalid"
    _clear_env()


def test_product_mismatch_is_rejected():
    """A valid key for a DIFFERENT Lemon Squeezy product must not unlock Shield."""
    with _scratch_shield_home():  # OGUNSCAN_PRODUCT_ID = 1086399
        L.write_license_key("KEY-OTHER-PRODUCT")
        with patch("ogunscan.shield.license._fetch_validate",
                   side_effect=lambda k, i, **kw: _ls_valid(product_id=999999)):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "product_mismatch"
    _clear_env()


def test_no_product_id_configured_accepts_any_valid_key():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["OGUNSCAN_SHIELD_HOME"] = tmp
        os.environ.pop("OGUNSCAN_PRODUCT_ID", None)
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate",
                   side_effect=lambda k, i, **kw: _ls_valid(product_id=999999)):
            status = L.verify_license()
        assert status.valid
        assert status.source == "remote"
    _clear_env()


def test_network_error_falls_back_to_stale_cache():
    """Customer paid — Lemon Squeezy downtime should not lock them out."""
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok):
            L.verify_license()  # warm cache
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_network_error):
            status = L.verify_license(ttl_seconds=0)  # force cache "stale"
        assert status.valid
        assert status.source == "stale_cache"
    _clear_env()


def test_network_error_and_no_cache_fails_clearly():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_network_error):
            status = L.verify_license()
        assert not status.valid
        assert status.source == "network_error"
        assert "internet" in status.message.lower()
    _clear_env()


def test_explicit_license_key_overrides_file():
    with _scratch_shield_home():
        L.write_license_key("KEY-FROM-FILE")
        with patch("ogunscan.shield.license._fetch_validate") as f:
            f.side_effect = lambda key, i, **kw: (
                _ls_valid() if key == "KEY-EXPLICIT"
                else {"valid": False, "error": "wrong"}
            )
            status = L.verify_license(license_key="KEY-EXPLICIT")
        assert status.valid
    _clear_env()


def test_clear_license_removes_files():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        L.write_instance_id("inst-abc")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok):
            L.verify_license()
        assert L.license_cache_path().exists()
        L.clear_license()
        assert not L.license_cache_path().exists()
        assert L.read_license_key() is None
        assert L.read_instance_id() is None
    _clear_env()


def test_deactivate_releases_seat_and_clears_local():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        L.write_instance_id("inst-abc")
        with patch("ogunscan.shield.license._fetch_deactivate") as f:
            f.return_value = {"deactivated": True}
            status = L.deactivate_license()
            f.assert_called_once()
        assert status.valid
        assert L.read_license_key() is None
        assert L.read_instance_id() is None
    _clear_env()


def test_read_license_key_handles_missing_file():
    with _scratch_shield_home():
        assert L.read_license_key() is None
    _clear_env()


def test_write_license_key_chmods_600():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        mode = oct(os.stat(L.license_file()).st_mode)[-3:]
        assert mode == "600", f"Expected 600, got {mode}"
    _clear_env()


def test_cache_freshness_check():
    from datetime import datetime, timezone, timedelta

    def w(seconds_ago):
        ts = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat().replace("+00:00", "Z")
        return {"verified_at": ts}
    assert L._cache_fresh(w(60), ttl_seconds=120)
    assert not L._cache_fresh(w(120), ttl_seconds=60)
    assert not L._cache_fresh({}, ttl_seconds=120)


def test_invalid_cache_json_treated_as_missing():
    with _scratch_shield_home():
        L.write_license_key("KEY-1234")
        L.license_cache_path().parent.mkdir(parents=True, exist_ok=True)
        L.license_cache_path().write_text("this is not json")
        with patch("ogunscan.shield.license._fetch_validate", side_effect=_fake_validate_ok) as f:
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
