"""License gate — Gumroad license-key verification with 24h cache.

Gumroad's license verify endpoint:

  POST https://api.gumroad.com/v2/licenses/verify
  body (form-encoded):
    product_id=<gumroad product id>
    license_key=<customer's key>
    increment_uses_count=false   (we count locally; don't burn Gumroad use slots)

  200 OK + {"success": true, ...} → valid
  200 OK + {"success": false, "message": "..."} → invalid
  other status → network / API error

Resolution flow at daemon start:

  1. If `license.key` file is missing → exit with activation message
  2. If `license.cache.json` is fresh (verified within 24h) → accept
  3. Else try a fresh verify against Gumroad:
     - success → accept, update cache
     - explicit invalid → exit with "license is invalid" message
     - network error → fall back to stale cache (offline tolerance);
       if no cache exists, soft-fail with a clear message

Per the doctrine: do NOT hard-fail mid-scan. License is checked at
daemon START only — once running, the daemon keeps going even if
Gumroad goes down or the cache expires.

Pure stdlib (urllib) for the HTTP call.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional

from .paths import ensure_dirs, license_file, shield_home


GUMROAD_VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify"
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
ACTIVATION_URL = "https://ogunscan.dev/shield"


def product_id() -> Optional[str]:
    """The Gumroad product ID for OgunScan Shield.

    Returned from env var `OGUNSCAN_PRODUCT_ID` so the value can be set
    deliberately at install/release time without rebuilding the package.
    The release pipeline bakes the production product ID into the wheel
    via a build-time env (see release.md). For development / testing,
    set OGUNSCAN_PRODUCT_ID in the local env or pass `product_id=` to
    `verify_license`.
    """
    return os.environ.get("OGUNSCAN_PRODUCT_ID")


def license_cache_path() -> Path:
    return shield_home() / "license.cache.json"


class LicenseStatus(NamedTuple):
    valid: bool
    source: str           # "cache" | "remote" | "stale_cache" | "missing" | "invalid" | "no_product_id"
    message: str
    purchase: Optional[Dict[str, Any]] = None


def read_license_key() -> Optional[str]:
    """Return the stored license key, or None if missing."""
    p = license_file()
    try:
        if not p.exists():
            return None
        return p.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def write_license_key(key: str) -> None:
    """Store the license key at ~/.ogunscan/shield/license.key (chmod 600)."""
    ensure_dirs()
    p = license_file()
    p.write_text(key, encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def clear_license() -> None:
    """Remove license key + cache file. Idempotent."""
    for p in (license_file(), license_cache_path()):
        try:
            p.unlink()
        except (OSError, FileNotFoundError):
            pass


def verify_license(
    license_key: Optional[str] = None,
    product_id_override: Optional[str] = None,
    ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    force_refresh: bool = False,
    timeout: int = 10,
) -> LicenseStatus:
    """Run the verify flow. Pure function over inputs + filesystem state.

    Parameters
    ----------
    license_key : if None, read from `~/.ogunscan/shield/license.key`.
    product_id_override : explicit product id for tests; default from env.
    ttl_seconds : cache freshness window (default 24h).
    force_refresh : skip cache, always hit Gumroad.
    timeout : HTTP request timeout.
    """
    key = license_key or read_license_key()
    if not key:
        return LicenseStatus(
            valid=False, source="missing",
            message=(
                "No OgunScan Shield license found. Run "
                "`ogunscan shield activate <license-key>` "
                f"or visit {ACTIVATION_URL} to purchase."
            ),
        )

    pid = product_id_override or product_id()
    if not pid:
        return LicenseStatus(
            valid=False, source="no_product_id",
            message=(
                "OgunScan Shield product id not configured. Set "
                "OGUNSCAN_PRODUCT_ID env var (the production wheel will "
                "have this baked in)."
            ),
        )

    # Cache hit — only if not forced refresh
    if not force_refresh:
        cached = _read_cache()
        if cached and cached.get("license_key") == key and _cache_fresh(cached, ttl_seconds):
            return LicenseStatus(
                valid=True, source="cache",
                message="License valid (cached, within 24h).",
                purchase=cached.get("purchase"),
            )

    # Network verify
    remote = _fetch_verify(pid, key, timeout=timeout)
    if remote is None:
        # Network unreachable. Fall back to stale cache rather than locking
        # the customer out of their own daemon — they paid for it.
        cached = _read_cache()
        if cached and cached.get("license_key") == key:
            return LicenseStatus(
                valid=True, source="stale_cache",
                message="License accepted from stale cache (Gumroad unreachable).",
                purchase=cached.get("purchase"),
            )
        return LicenseStatus(
            valid=False, source="network_error",
            message=(
                "Could not reach Gumroad to verify the license and no "
                "cached verification is available. Check your internet "
                f"connection or visit {ACTIVATION_URL}."
            ),
        )

    if remote.get("success") is True:
        purchase = remote.get("purchase") or {}
        _write_cache({"license_key": key, "verified_at": _now_iso(), "purchase": purchase})
        return LicenseStatus(
            valid=True, source="remote",
            message="License valid (verified just now with Gumroad).",
            purchase=purchase,
        )

    # success=False from Gumroad → genuinely invalid
    msg = remote.get("message") or "License key was rejected by Gumroad."
    return LicenseStatus(
        valid=False, source="invalid",
        message=f"License invalid: {msg} Visit {ACTIVATION_URL} for help.",
    )


# ── internals ────────────────────────────────────────────────────────────


def _fetch_verify(pid: str, key: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Call Gumroad's verify endpoint. Returns parsed JSON on any HTTP
    response (success or not), or None if the request itself failed (network
    error, timeout, etc.)."""
    data = urllib.parse.urlencode({
        "product_id": pid,
        "license_key": key,
        "increment_uses_count": "false",
    }).encode("utf-8")
    req = urllib.request.Request(
        GUMROAD_VERIFY_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "ogunscan-shield/1",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        # Gumroad returns 404 with body {"success": false, ...} for unknown keys.
        # Treat that as an authoritative "invalid" rather than a network error.
        try:
            body = e.read().decode("utf-8")
        except Exception:
            return None
    except (urllib.error.URLError, TimeoutError, OSError, ConnectionError):
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def _read_cache() -> Optional[Dict[str, Any]]:
    p = license_cache_path()
    try:
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(data: Dict[str, Any]) -> None:
    ensure_dirs()
    p = license_cache_path()
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    except OSError:
        # Cache failure is non-fatal — next verify just won't have a cache hit
        pass


def _cache_fresh(cached: Dict[str, Any], ttl_seconds: int) -> bool:
    iso = cached.get("verified_at")
    if not iso:
        return False
    try:
        ts = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age < ttl_seconds


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
