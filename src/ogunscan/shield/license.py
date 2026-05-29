"""License gate — Lemon Squeezy license-key verification with 24h cache.

OgunScan Shield is sold as a Lemon Squeezy subscription with license keys ON.
Lemon Squeezy (unlike Gumroad memberships) issues real license keys for
subscription products and exposes a public License API for validation,
activation, and deactivation:

  POST https://api.lemonsqueezy.com/v1/licenses/validate
    body (form-encoded): license_key=<key>  [instance_id=<id>]
  POST https://api.lemonsqueezy.com/v1/licenses/activate
    body (form-encoded): license_key=<key>  instance_name=<hostname>
  POST https://api.lemonsqueezy.com/v1/licenses/deactivate
    body (form-encoded): license_key=<key>  instance_id=<id>

These three endpoints are public — they take NO Authorization header (the
license key itself is the credential). Response shape (validate / activate):

  {
    "valid": true,
    "error": null,
    "license_key": {"id", "status", "key", "activation_limit",
                    "activation_usage", "created_at", "expires_at"},
    "instance":    {"id", "name", "created_at"} | null,
    "meta":        {"store_id", "product_id", "product_name",
                    "variant_id", "customer_id", "customer_name",
                    "customer_email"}
  }

`license_key.status` is one of: active | inactive | expired | disabled.

Activation model (the meaningful difference from Gumroad):

  - `activate` registers THIS machine as an instance against the key and
    returns an `instance.id`. We persist that id alongside the key.
  - `validate` is then called with both key + instance_id, so a single
    seat can't be shared across unlimited machines (Lemon Squeezy enforces
    the activation_limit server-side).

Resolution flow at daemon start (verify_license → validate):

  1. If `license.key` is missing → exit with activation message
  2. If `license.cache.json` is fresh (verified within 24h) → accept
  3. Else validate against Lemon Squeezy:
     - valid=true (+ product matches, if configured) → accept, update cache
     - valid=false → exit with "license is invalid" message
     - network error → fall back to stale cache (offline tolerance);
       if no cache exists, soft-fail with a clear message

Per the doctrine: do NOT hard-fail mid-scan. License is checked at daemon
START only — once running, the daemon keeps going even if Lemon Squeezy
goes down or the cache expires.

Pure stdlib (urllib) for the HTTP calls.
"""

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional

from .paths import ensure_dirs, license_file, shield_home


LS_API_BASE = "https://api.lemonsqueezy.com/v1"
LS_VALIDATE_URL = f"{LS_API_BASE}/licenses/validate"
LS_ACTIVATE_URL = f"{LS_API_BASE}/licenses/activate"
LS_DEACTIVATE_URL = f"{LS_API_BASE}/licenses/deactivate"

DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
ACTIVATION_URL = "https://store.ten30studio.com"

# Lemon Squeezy license_key.status values that mean "this seat may run".
# `inactive` is included because a freshly purchased key is `inactive` until
# its first activation; our activate flow promotes it to `active`, but a
# validate that races ahead of the status flip should not lock the buyer out.
VALID_LICENSE_STATUSES = frozenset({"active", "inactive"})


def product_id() -> Optional[str]:
    """The Lemon Squeezy product ID for OgunScan Shield.

    Returned from env var `OGUNSCAN_PRODUCT_ID`. When set, a validated key's
    `meta.product_id` MUST match it — this stops a license for a *different*
    Ten30 Lemon Squeezy product from unlocking Shield. The release pipeline
    bakes the production product ID (`1086399`) into the wheel via a
    build-time env. When unset, the product check is skipped (any valid key
    from the store is accepted) — useful for local dev.
    """
    return os.environ.get("OGUNSCAN_PRODUCT_ID")


def license_cache_path() -> Path:
    return shield_home() / "license.cache.json"


def license_instance_path() -> Path:
    return shield_home() / "license.instance"


class LicenseStatus(NamedTuple):
    valid: bool
    source: str           # cache | remote | stale_cache | missing | invalid | network_error | product_mismatch
    message: str
    purchase: Optional[Dict[str, Any]] = None


# ── stored credentials (key + activation instance) ─────────────────────────


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


def read_instance_id() -> Optional[str]:
    """Return the Lemon Squeezy activation instance id for this machine, if any."""
    p = license_instance_path()
    try:
        if not p.exists():
            return None
        return p.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def write_instance_id(instance_id: str) -> None:
    ensure_dirs()
    p = license_instance_path()
    p.write_text(instance_id, encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def clear_license() -> None:
    """Remove license key, cache, and activation instance. Idempotent.

    Note: this only clears LOCAL state. To free the seat server-side, call
    `deactivate_license` first (the CLI `deactivate` command does both).
    """
    for p in (license_file(), license_cache_path(), license_instance_path()):
        try:
            p.unlink()
        except (OSError, FileNotFoundError):
            pass


# ── public operations ──────────────────────────────────────────────────────


def activate_license(
    license_key: str,
    product_id_override: Optional[str] = None,
    instance_name: Optional[str] = None,
    timeout: int = 10,
) -> LicenseStatus:
    """Register THIS machine as an activation against `license_key`.

    On success, persists the key + the returned instance id and warms the
    verification cache. This is what `ogunscan shield activate <key>` calls.
    """
    key = (license_key or "").strip()
    if not key:
        return LicenseStatus(valid=False, source="invalid", message="License key cannot be empty.")

    name = instance_name or _default_instance_name()
    resp = _fetch_activate(key, name, timeout=timeout)
    if resp is None:
        return LicenseStatus(
            valid=False, source="network_error",
            message=(
                "Could not reach Lemon Squeezy to activate the license. "
                f"Check your internet connection or visit {ACTIVATION_URL}."
            ),
        )

    if not resp.get("valid"):
        msg = resp.get("error") or "License key was rejected by Lemon Squeezy."
        return LicenseStatus(
            valid=False, source="invalid",
            message=f"License invalid: {msg} Visit {ACTIVATION_URL} for help.",
        )

    pid_status = _check_product(resp)
    if pid_status is not None:
        return pid_status

    instance = resp.get("instance") or {}
    instance_id = str(instance.get("id") or "")
    write_license_key(key)
    if instance_id:
        write_instance_id(instance_id)
    purchase = _purchase_from_meta(resp)
    _write_cache({
        "license_key": key,
        "instance_id": instance_id,
        "verified_at": _now_iso(),
        "purchase": purchase,
    })
    return LicenseStatus(
        valid=True, source="remote",
        message="License activated with Lemon Squeezy.",
        purchase=purchase,
    )


def deactivate_license(timeout: int = 10) -> LicenseStatus:
    """Release this machine's seat server-side (best effort), then clear local state."""
    key = read_license_key()
    instance_id = read_instance_id()
    if key and instance_id:
        _fetch_deactivate(key, instance_id, timeout=timeout)  # best-effort; ignore result
    clear_license()
    return LicenseStatus(valid=True, source="remote", message="License deactivated and local state cleared.")


def verify_license(
    license_key: Optional[str] = None,
    product_id_override: Optional[str] = None,
    ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    force_refresh: bool = False,
    timeout: int = 10,
) -> LicenseStatus:
    """Validate the stored (or supplied) license. Pure function over inputs +
    filesystem state.

    Parameters
    ----------
    license_key : if None, read from `~/.ogunscan/shield/license.key`.
    product_id_override : explicit product id for tests; default from env.
    ttl_seconds : cache freshness window (default 24h).
    force_refresh : skip cache, always hit Lemon Squeezy.
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

    # Cache hit — only if not forced refresh
    if not force_refresh:
        cached = _read_cache()
        if cached and cached.get("license_key") == key and _cache_fresh(cached, ttl_seconds):
            return LicenseStatus(
                valid=True, source="cache",
                message="License valid (cached, within 24h).",
                purchase=cached.get("purchase"),
            )

    instance_id = read_instance_id()
    resp = _fetch_validate(key, instance_id, timeout=timeout)
    if resp is None:
        # Network unreachable. Fall back to stale cache rather than locking the
        # customer out of their own daemon — they paid for it.
        cached = _read_cache()
        if cached and cached.get("license_key") == key:
            return LicenseStatus(
                valid=True, source="stale_cache",
                message="License accepted from stale cache (Lemon Squeezy unreachable).",
                purchase=cached.get("purchase"),
            )
        return LicenseStatus(
            valid=False, source="network_error",
            message=(
                "Could not reach Lemon Squeezy to verify the license and no "
                "cached verification is available. Check your internet "
                f"connection or visit {ACTIVATION_URL}."
            ),
        )

    if not resp.get("valid"):
        msg = resp.get("error") or "License key was rejected by Lemon Squeezy."
        return LicenseStatus(
            valid=False, source="invalid",
            message=f"License invalid: {msg} Visit {ACTIVATION_URL} for help.",
        )

    # valid=true — enforce status + product, then accept
    lk = resp.get("license_key") or {}
    status = (lk.get("status") or "").lower()
    if status and status not in VALID_LICENSE_STATUSES:
        return LicenseStatus(
            valid=False, source="invalid",
            message=(
                f"License is {status} (not active). "
                f"Renew or check your subscription at {ACTIVATION_URL}."
            ),
        )

    pid_status = _check_product(resp, product_id_override=product_id_override)
    if pid_status is not None:
        return pid_status

    purchase = _purchase_from_meta(resp)
    _write_cache({
        "license_key": key,
        "instance_id": instance_id or "",
        "verified_at": _now_iso(),
        "purchase": purchase,
    })
    return LicenseStatus(
        valid=True, source="remote",
        message="License valid (verified just now with Lemon Squeezy).",
        purchase=purchase,
    )


# ── internals ────────────────────────────────────────────────────────────


def _default_instance_name() -> str:
    try:
        return socket.gethostname() or "ogunscan-shield"
    except OSError:
        return "ogunscan-shield"


def _check_product(resp: Dict[str, Any], product_id_override: Optional[str] = None) -> Optional[LicenseStatus]:
    """Return a product_mismatch LicenseStatus if a product id is configured and
    the validated key belongs to a different product. Returns None when the key
    is fine (or no product id is configured)."""
    pid = product_id_override or product_id()
    if not pid:
        return None
    meta = resp.get("meta") or {}
    returned = meta.get("product_id")
    if returned is None or str(returned) == str(pid):
        return None
    return LicenseStatus(
        valid=False, source="product_mismatch",
        message=(
            "This license key is valid but belongs to a different product. "
            f"Purchase OgunScan Shield at {ACTIVATION_URL}."
        ),
    )


def _purchase_from_meta(resp: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the bits of a Lemon Squeezy response worth showing the user."""
    meta = resp.get("meta") or {}
    lk = resp.get("license_key") or {}
    out: Dict[str, Any] = {}
    if meta.get("customer_email"):
        out["email"] = meta["customer_email"]
    if meta.get("customer_name"):
        out["customer_name"] = meta["customer_name"]
    if meta.get("product_name"):
        out["product_name"] = meta["product_name"]
    if lk.get("status"):
        out["status"] = lk["status"]
    if lk.get("expires_at"):
        out["expires_at"] = lk["expires_at"]
    if lk.get("created_at"):
        out["created_at"] = lk["created_at"]
    return out


def _ls_post(url: str, fields: Dict[str, str], timeout: int) -> Optional[Dict[str, Any]]:
    """POST form-encoded fields to a Lemon Squeezy public license endpoint.

    Returns parsed JSON on any HTTP response (Lemon Squeezy returns 400 with a
    JSON body `{"valid": false, "error": ...}` for bad keys), or None if the
    request itself failed (network error, timeout, non-JSON)."""
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "ogunscan-shield/2",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        # 400/404 carry an authoritative JSON body — treat as a real answer,
        # not a transport failure.
        try:
            body = e.read().decode("utf-8")
        except Exception:
            return None
    except (urllib.error.URLError, TimeoutError, OSError, ConnectionError):
        return None
    try:
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _fetch_validate(key: str, instance_id: Optional[str], timeout: int) -> Optional[Dict[str, Any]]:
    fields = {"license_key": key}
    if instance_id:
        fields["instance_id"] = instance_id
    return _ls_post(LS_VALIDATE_URL, fields, timeout=timeout)


def _fetch_activate(key: str, instance_name: str, timeout: int) -> Optional[Dict[str, Any]]:
    return _ls_post(LS_ACTIVATE_URL, {"license_key": key, "instance_name": instance_name}, timeout=timeout)


def _fetch_deactivate(key: str, instance_id: str, timeout: int) -> Optional[Dict[str, Any]]:
    return _ls_post(LS_DEACTIVATE_URL, {"license_key": key, "instance_id": instance_id}, timeout=timeout)


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
