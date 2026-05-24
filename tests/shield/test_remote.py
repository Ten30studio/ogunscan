"""Tests for shield/remote.py — TLS cert checks, HTTPS detection,
response-header analysis, status probing. All network is mocked; the
live HTTP path is exercised when the customer actually runs Shield
against a registered endpoint.
"""

import sys
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.shield.remote import probe_endpoint, SUSPICIOUS_RESPONSE_HEADERS


def _http_ok_no_disclosure(method, timeout):
    """Helper: return a clean (status=200, no suspicious headers) response."""
    return 200, _Hdrs({})


class _Hdrs:
    """Minimal header dict that mimics email.Message's case-insensitive get."""
    def __init__(self, d):
        self._d = {k.lower(): v for k, v in d.items()}
    def get(self, key, default=None):
        return self._d.get(key.lower(), default)


# ── HTTP scheme detection ─────────────────────────────────────────────────


def test_http_url_flags_OGN_602_critical():
    """Plain http:// URL must fire OGN-602 (CRITICAL) — passive MITM trivial."""
    with patch("ogunscan.shield.remote._request", return_value=(200, _Hdrs({}))):
        findings = probe_endpoint("http://insecure.example.com/mcp", name="insecure")
    rules = [f.rule_id for f in findings]
    assert "OGN-602" in rules
    sev = next(f for f in findings if f.rule_id == "OGN-602").severity.value
    assert sev == "CRITICAL"


def test_unknown_scheme_is_flagged():
    """ftp:// or anything non-https/http should surface."""
    with patch("ogunscan.shield.remote._request", return_value=(None, None)):
        findings = probe_endpoint("ftp://weird.example.com/mcp", name="weird")
    assert any(f.rule_id == "OGN-602" for f in findings)


def test_https_with_clean_cert_and_no_disclosure_emits_no_findings():
    """The happy path: valid cert, 200 OK, no leaky headers → zero findings."""
    future = datetime.now(timezone.utc) + timedelta(days=180)
    fake_cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("ogunscan.shield.remote._probe_tls_cert", return_value=[]), \
         patch("ogunscan.shield.remote._request", return_value=(200, _Hdrs({}))):
        findings = probe_endpoint("https://clean.example.com/mcp", name="clean")
    assert findings == []


# ── TLS cert expiry ───────────────────────────────────────────────────────


def test_cert_expiring_in_5_days_fires_OGN_600_high():
    """Within the 14-day warn window → HIGH."""
    soon = datetime.now(timezone.utc) + timedelta(days=5)
    fake_cert = {"notAfter": soon.strftime("%b %d %H:%M:%S %Y GMT")}
    fake_sock = MagicMock()
    fake_sock.__enter__.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request", return_value=(200, _Hdrs({}))):
        # Wire the SSLContext.wrap_socket to return the fake cert
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://expiring-soon.example.com/mcp", name="expiring")
    rules = [f.rule_id for f in findings]
    assert "OGN-600" in rules
    sev = next(f for f in findings if f.rule_id == "OGN-600").severity.value
    assert sev == "HIGH"


def test_cert_already_expired_fires_OGN_601_critical():
    """Cert with notAfter in the past → CRITICAL."""
    past = datetime.now(timezone.utc) - timedelta(days=3)
    fake_cert = {"notAfter": past.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request", return_value=(200, _Hdrs({}))):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://expired.example.com/mcp", name="expired")
    rules = [f.rule_id for f in findings]
    assert "OGN-601" in rules
    sev = next(f for f in findings if f.rule_id == "OGN-601").severity.value
    assert sev == "CRITICAL"


def test_ssl_cert_verification_error_fires_OGN_601():
    """If the TLS handshake fails verification (expired/wrong host/self-signed),
    we emit OGN-601 even before getting a parsed cert."""
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx:
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            1, "certificate has expired"
        )
        findings = probe_endpoint("https://bad-cert.example.com/mcp", name="bad")
    rules = [f.rule_id for f in findings]
    assert "OGN-601" in rules


def test_cert_far_in_future_emits_no_cert_finding():
    """200 days out → no cert finding."""
    far = datetime.now(timezone.utc) + timedelta(days=200)
    fake_cert = {"notAfter": far.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request", return_value=(200, _Hdrs({}))):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://safe.example.com/mcp", name="safe")
    cert_rules = [f.rule_id for f in findings if f.rule_id in ("OGN-600", "OGN-601")]
    assert cert_rules == []


# ── HTTP status ───────────────────────────────────────────────────────────


def test_500_response_fires_OGN_603_high():
    """5xx response → HIGH (server consistently failing)."""
    far = datetime.now(timezone.utc) + timedelta(days=180)
    fake_cert = {"notAfter": far.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request", return_value=(500, _Hdrs({}))):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://broken.example.com/mcp", name="broken")
    rules = [f.rule_id for f in findings]
    assert "OGN-603" in rules


def test_unreachable_endpoint_fires_OGN_603():
    """Network/DNS error → unreachable → HIGH."""
    far = datetime.now(timezone.utc) + timedelta(days=180)
    fake_cert = {"notAfter": far.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request", return_value=(None, None)):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://gone.example.com/mcp", name="gone")
    rules = [f.rule_id for f in findings]
    assert "OGN-603" in rules


# ── Response header disclosure ────────────────────────────────────────────


def test_server_header_with_version_fires_OGN_604_medium():
    """`Server: nginx/1.18.0` → MEDIUM."""
    far = datetime.now(timezone.utc) + timedelta(days=180)
    fake_cert = {"notAfter": far.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request",
               return_value=(200, _Hdrs({"Server": "nginx/1.18.0"}))):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://leaky.example.com/mcp", name="leaky")
    rules = [f.rule_id for f in findings]
    assert "OGN-604" in rules
    sev = next(f for f in findings if f.rule_id == "OGN-604").severity.value
    assert sev == "MEDIUM"


def test_xpoweredby_header_fires_OGN_604():
    """`X-Powered-By: Express` → MEDIUM."""
    far = datetime.now(timezone.utc) + timedelta(days=180)
    fake_cert = {"notAfter": far.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request",
               return_value=(200, _Hdrs({"X-Powered-By": "Express"}))):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://express.example.com/mcp", name="express")
    rules = [f.rule_id for f in findings]
    assert "OGN-604" in rules


def test_server_header_without_version_does_not_fire():
    """`Server: nginx` (no version) → no finding."""
    far = datetime.now(timezone.utc) + timedelta(days=180)
    fake_cert = {"notAfter": far.strftime("%b %d %H:%M:%S %Y GMT")}
    with patch("socket.create_connection") as conn, \
         patch("ssl.create_default_context") as ctx, \
         patch("ogunscan.shield.remote._request",
               return_value=(200, _Hdrs({"Server": "nginx"}))):
        conn.return_value.__enter__.return_value = MagicMock()
        ctx.return_value.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = fake_cert
        findings = probe_endpoint("https://clean.example.com/mcp", name="clean")
    assert not any(f.rule_id == "OGN-604" for f in findings)


# ── Identity for diff ────────────────────────────────────────────────────


def test_finding_location_is_the_url():
    """Finding identity = (rule_id, location) — location must be the URL
    so re-probing the same endpoint diffs correctly."""
    with patch("ogunscan.shield.remote._request", return_value=(200, _Hdrs({}))):
        findings = probe_endpoint("http://example.com/mcp", name="x")
    http_finding = next(f for f in findings if f.rule_id == "OGN-602")
    assert http_finding.location == "http://example.com/mcp"


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
