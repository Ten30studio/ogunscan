"""Remote endpoint probing — Shield's private-server scanning.

Customers register remote MCP server endpoints (`ogunscan shield add
--remote <url> <name>`); the daemon probes them on each scheduled scan
cycle and emits Finding objects through the same alert pipeline used
for local config scans.

Checks performed per endpoint:

  OGN-600 (HIGH)     — TLS certificate expires within `CERT_EXPIRY_WARN_DAYS`
                       (default 14 days)
  OGN-601 (CRITICAL) — TLS certificate already expired
  OGN-602 (CRITICAL) — Remote endpoint serves HTTP (not HTTPS) — passive
                       MITM trivial
  OGN-603 (HIGH)     — Remote endpoint returns a non-success HTTP status
                       (≥400) — likely misconfigured or hostile
  OGN-604 (MEDIUM)   — Response header discloses unnecessary information
                       (Server: with version, X-Powered-By, etc.)

Pure stdlib: urllib + ssl + socket. Zero added deps.

Findings use the same Finding dataclass and feed the same diff/notify
pipeline as local-config findings. Identity (rule_id, location) where
location = `<url>` so cert-warning at https://x.com is one finding,
even if probed many times.
"""

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ..models import Finding, Severity


CERT_EXPIRY_WARN_DAYS = 14
REQUEST_TIMEOUT_SECONDS = 10

# Response headers that disclose software identity / version. Each entry:
#   (header_name, regex_to_match, human_label)
SUSPICIOUS_RESPONSE_HEADERS = [
    ("Server", r".*\d+\.\d+.*", "Server header discloses software version"),
    ("X-Powered-By", r".+", "X-Powered-By header discloses framework"),
    ("X-AspNet-Version", r".+", "X-AspNet-Version header discloses ASP.NET version"),
    ("X-AspNetMvc-Version", r".+", "X-AspNetMvc-Version header discloses MVC version"),
]


def probe_endpoint(
    url: str,
    name: Optional[str] = None,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    cert_warn_days: int = CERT_EXPIRY_WARN_DAYS,
    now: Optional[datetime] = None,
) -> List[Finding]:
    """Probe one remote endpoint and return any findings.

    Parameters
    ----------
    url : full URL of the endpoint (e.g. https://api.example.com/mcp)
    name : friendly name the customer registered. Used in finding text.
    timeout : per-network-call timeout in seconds.
    cert_warn_days : warn if TLS cert expires within this many days.
    now : injectable for tests. Defaults to datetime.now(UTC).
    """
    findings: List[Finding] = []
    display = name or url
    location = url  # stable identity for diff

    parsed = urllib.parse.urlparse(url)

    # OGN-602: HTTPS check. HTTP MCP traffic is a passive-MITM trivial-win.
    if parsed.scheme == "http":
        findings.append(Finding(
            rule_id="OGN-602",
            severity=Severity.CRITICAL,
            title=f"Remote MCP server serves HTTP (not HTTPS): {display}",
            description=(
                f"Endpoint '{display}' uses plain HTTP. All MCP traffic — "
                f"tool calls, responses, any embedded credentials — is "
                f"observable to anyone on the network path. Passive MITM."
            ),
            location=location,
            remediation=(
                "Migrate the endpoint to HTTPS. Use a real TLS certificate "
                "(Let's Encrypt is free + auto-renewing). Never run remote "
                "MCP over HTTP, even on 'internal' networks."
            ),
            evidence=url,
        ))
        # No point continuing TLS checks against HTTP
        # but DO still probe status (next block)
        status_findings = _probe_http_status(url, timeout=timeout, display=display, location=location)
        findings.extend(status_findings)
        return findings

    # HTTPS path — TLS cert + status + headers
    if parsed.scheme != "https":
        # Unknown scheme — surface as a finding so customer notices
        findings.append(Finding(
            rule_id="OGN-602",
            severity=Severity.HIGH,
            title=f"Remote MCP server URL has unexpected scheme '{parsed.scheme}': {display}",
            description=f"Expected https://; got '{parsed.scheme}://...'. Cannot probe.",
            location=location,
            remediation="Use an https:// URL for remote MCP endpoints.",
            evidence=url,
        ))
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    # TLS cert checks
    cert_findings = _probe_tls_cert(
        host=host, port=port,
        timeout=timeout, display=display, location=location,
        cert_warn_days=cert_warn_days, now=now or datetime.now(timezone.utc),
    )
    findings.extend(cert_findings)

    # Status + header checks (only if TLS handshake was OK enough to talk HTTP)
    cert_critical = any(f.rule_id == "OGN-601" for f in cert_findings)
    if not cert_critical:
        findings.extend(_probe_http_status(url, timeout=timeout, display=display, location=location))
        findings.extend(_probe_response_headers(url, timeout=timeout, display=display, location=location))

    return findings


# ── internals ────────────────────────────────────────────────────────────


def _probe_tls_cert(
    host: str, port: int, timeout: int, display: str, location: str,
    cert_warn_days: int, now: datetime,
) -> List[Finding]:
    """Open a TLS socket and inspect the server cert. Returns OGN-600 / OGN-601
    findings as warranted. Network/TLS errors yield no findings (they manifest
    via the HTTP-status probe instead)."""
    out: List[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        # Cert that doesn't verify is itself a finding — usually expired,
        # self-signed, or wrong host.
        msg = str(e)
        if "certificate has expired" in msg.lower() or "expired" in msg.lower():
            out.append(Finding(
                rule_id="OGN-601",
                severity=Severity.CRITICAL,
                title=f"Remote MCP server TLS certificate has EXPIRED: {display}",
                description=f"TLS verification failed: {msg}. The certificate is past its notAfter date.",
                location=location,
                remediation=(
                    "Renew the TLS certificate immediately. Use Let's Encrypt + "
                    "auto-renewal (certbot, caddy, etc.) so this doesn't recur."
                ),
                evidence=msg[:200],
            ))
        else:
            out.append(Finding(
                rule_id="OGN-601",
                severity=Severity.CRITICAL,
                title=f"Remote MCP server TLS certificate failed verification: {display}",
                description=f"TLS verification failed: {msg}",
                location=location,
                remediation="Fix the certificate or hostname mismatch. Untrusted TLS is unsafe.",
                evidence=msg[:200],
            ))
        return out
    except (socket.timeout, OSError, ssl.SSLError):
        # Network unreachable / TLS handshake failure that isn't a cert-verify
        # error — silent; the HTTP probe will note connection failure.
        return out

    not_after_raw = cert.get("notAfter")
    if not not_after_raw:
        return out
    try:
        # Python's cert dict has notAfter in format like 'Jul 23 12:00:00 2026 GMT'
        not_after = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
    except ValueError:
        return out

    days_left = (not_after - now).total_seconds() / 86400.0
    if days_left < 0:
        # Already expired but verify_mode accepted? Unusual but possible if
        # the validator is lenient. Treat as OGN-601.
        out.append(Finding(
            rule_id="OGN-601",
            severity=Severity.CRITICAL,
            title=f"Remote MCP server TLS certificate EXPIRED: {display}",
            description=f"Certificate expired {int(-days_left)} days ago (notAfter={not_after_raw}).",
            location=location,
            remediation="Renew the TLS certificate immediately. Configure auto-renewal.",
            evidence=not_after_raw,
        ))
    elif days_left <= cert_warn_days:
        out.append(Finding(
            rule_id="OGN-600",
            severity=Severity.HIGH,
            title=f"Remote MCP server TLS certificate expiring soon: {display}",
            description=f"Certificate expires in {int(days_left)} days (notAfter={not_after_raw}).",
            location=location,
            remediation="Renew the TLS certificate before it expires. Use Let's Encrypt + auto-renewal.",
            evidence=not_after_raw,
        ))
    return out


def _probe_http_status(url: str, timeout: int, display: str, location: str) -> List[Finding]:
    """Issue a HEAD; fall back to GET if the server rejects HEAD."""
    out: List[Finding] = []
    status, _ = _request(url, method="HEAD", timeout=timeout)
    if status is None:
        # HEAD failed for transport reasons — try GET
        status, _ = _request(url, method="GET", timeout=timeout)
    if status is None:
        out.append(Finding(
            rule_id="OGN-603",
            severity=Severity.HIGH,
            title=f"Remote MCP server unreachable: {display}",
            description=f"No HTTP response from {url} (network / DNS / TLS error).",
            location=location,
            remediation="Verify the endpoint URL, DNS, firewall rules, and TLS configuration.",
            evidence=url,
        ))
    elif status == 405:
        # HEAD unsupported, GET worked → status came from GET attempt's first try.
        # This isn't an error per se. Re-run GET to confirm.
        get_status, _ = _request(url, method="GET", timeout=timeout)
        if get_status is None or get_status >= 400:
            out.append(Finding(
                rule_id="OGN-603",
                severity=Severity.HIGH,
                title=f"Remote MCP server returns non-success status: {display}",
                description=f"GET {url} → HTTP {get_status}",
                location=location,
                remediation="Check server logs. A consistently failing MCP endpoint is unusable.",
                evidence=f"HTTP {get_status}",
            ))
    elif status >= 400:
        out.append(Finding(
            rule_id="OGN-603",
            severity=Severity.HIGH,
            title=f"Remote MCP server returns non-success status: {display}",
            description=f"{url} → HTTP {status}",
            location=location,
            remediation="Check server logs. A consistently failing MCP endpoint is unusable.",
            evidence=f"HTTP {status}",
        ))
    return out


def _probe_response_headers(url: str, timeout: int, display: str, location: str) -> List[Finding]:
    """Pull response headers, flag any that disclose stack details."""
    out: List[Finding] = []
    status, headers = _request(url, method="HEAD", timeout=timeout)
    if headers is None:
        status, headers = _request(url, method="GET", timeout=timeout)
    if not headers:
        return out
    for header_name, pattern, label in SUSPICIOUS_RESPONSE_HEADERS:
        value = headers.get(header_name)
        if value and re.match(pattern, value):
            out.append(Finding(
                rule_id="OGN-604",
                severity=Severity.MEDIUM,
                title=f"Suspicious response header on remote MCP server: {label}",
                description=(
                    f"Endpoint '{display}' returns '{header_name}: {value}'. "
                    f"This discloses software identity to anyone who probes the URL, "
                    f"making CVE-targeted attacks easier."
                ),
                location=location,
                remediation=(
                    f"Configure the server to omit or sanitize the {header_name} response "
                    f"header. (nginx: `server_tokens off;` — apache: `ServerTokens Prod` + "
                    f"`ServerSignature Off` — express.js: `app.disable('x-powered-by')`)."
                ),
                evidence=f"{header_name}: {value}",
            ))
    return out


def _request(url: str, method: str, timeout: int):
    """Issue an HTTP request. Returns (status, headers_dict) or (None, None)
    on transport failure. headers_dict is case-insensitive lookup."""
    req = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": "ogunscan-shield-probe/1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _CaseInsensitiveHeaders(resp.headers)
    except urllib.error.HTTPError as e:
        # 4xx / 5xx still give us headers + status
        return e.code, _CaseInsensitiveHeaders(getattr(e, "headers", {}))
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError, TimeoutError):
        return None, None


class _CaseInsensitiveHeaders:
    """Wrap email.Message-like headers with case-insensitive .get()."""
    def __init__(self, headers):
        self._h = headers

    def get(self, key: str, default=None):
        if self._h is None:
            return default
        if hasattr(self._h, "get"):
            v = self._h.get(key, None)
            if v is not None:
                return v
            # Try case variants
            for k, val in (self._h.items() if hasattr(self._h, "items") else []):
                if k.lower() == key.lower():
                    return val
        return default
