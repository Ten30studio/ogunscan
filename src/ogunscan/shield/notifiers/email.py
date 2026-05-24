"""EmailNotifier — sends Shield alerts via SMTP.

Designed for Gmail SMTP via Google Workspace app password (the most
common setup for our customer-local install model), but works with any
SMTP server that supports STARTTLS on the standard ports.

Env vars (all required for the notifier to enable itself):

  OGUNSCAN_SMTP_HOST       e.g. smtp.gmail.com
  OGUNSCAN_SMTP_PORT       e.g. 587 (STARTTLS) or 465 (implicit TLS)
  OGUNSCAN_SMTP_USER       sender address, e.g. admin@ten30studio.com
  OGUNSCAN_SMTP_APP_PASS   the SMTP password (Gmail "app password", 16 chars)
  OGUNSCAN_ALERT_EMAIL     recipient address (can be same as USER)

The notifier is safe to instantiate without env vars — `is_configured()`
returns False and the daemon's auto-wiring skips it.
"""

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

from ...models import Finding, Severity
from .base import Notifier


SEVERITY_COLOR = {
    Severity.CRITICAL: "#B22222",  # firebrick
    Severity.HIGH:     "#D2691E",  # chocolate
    Severity.MEDIUM:   "#B8860B",  # darkgoldenrod
    Severity.LOW:      "#4682B4",  # steelblue
    Severity.INFO:     "#708090",  # slategray
}

SEVERITY_BADGE_TEXT_COLOR = "#FFFFFF"


class EmailNotifier(Notifier):
    name = "email"

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        recipient: Optional[str] = None,
    ):
        self.host = host or os.environ.get("OGUNSCAN_SMTP_HOST")
        port_env = port if port is not None else os.environ.get("OGUNSCAN_SMTP_PORT")
        try:
            self.port = int(port_env) if port_env else None
        except (TypeError, ValueError):
            self.port = None
        self.user = user or os.environ.get("OGUNSCAN_SMTP_USER")
        # Gmail app passwords come with spaces for human readability — strip them
        raw_pw = password if password is not None else os.environ.get("OGUNSCAN_SMTP_APP_PASS")
        self.password = raw_pw.replace(" ", "") if raw_pw else None
        self.recipient = recipient or os.environ.get("OGUNSCAN_ALERT_EMAIL") or self.user

    @classmethod
    def from_env(cls) -> Optional["EmailNotifier"]:
        """Return an EmailNotifier if env is configured, else None.
        The daemon's auto-wiring uses this to decide whether to enable email."""
        instance = cls()
        return instance if instance.is_configured() else None

    def is_configured(self) -> bool:
        return all([self.host, self.port, self.user, self.password, self.recipient])

    # ── Notifier interface ────────────────────────────────────────────────

    def notify_new(self, finding: Finding, scan_path: str) -> None:
        if not self.is_configured():
            return
        subject = self._subject(finding, scan_path, kind="NEW")
        plain = self._plain_body(finding, scan_path, kind="NEW")
        html = self._html_body(finding, scan_path, kind="NEW")
        self._send(subject, plain, html)

    def notify_resolved(self, finding: Finding, scan_path: str) -> None:
        if not self.is_configured():
            return
        subject = self._subject(finding, scan_path, kind="RESOLVED")
        plain = self._plain_body(finding, scan_path, kind="RESOLVED")
        html = self._html_body(finding, scan_path, kind="RESOLVED")
        self._send(subject, plain, html)

    def notify_scan_summary(self, scan_path: str, total_new: int, total_resolved: int, total_unchanged: int) -> None:
        # Per-finding emails already cover the surface; a per-scan summary email
        # would double-deliver. Skip — Slack summaries are noisier-channel-tolerant.
        return

    # ── message construction ──────────────────────────────────────────────

    def _subject(self, finding: Finding, scan_path: str, kind: str) -> str:
        if kind == "NEW":
            return f"[OgunScan Shield] {finding.severity.value} {finding.rule_id} — {finding.title}"
        return f"[OgunScan Shield] RESOLVED {finding.rule_id} at {finding.location}"

    def _plain_body(self, finding: Finding, scan_path: str, kind: str) -> str:
        if kind == "RESOLVED":
            return (
                f"OgunScan Shield — finding RESOLVED\n"
                f"\n"
                f"Rule:      {finding.rule_id}\n"
                f"Location:  {finding.location}\n"
                f"Scanned:   {scan_path}\n"
                f"\n"
                f"The finding is no longer present in the most recent scan.\n"
                f"\n"
                f"— OgunScan Shield (https://ogunscan.dev)\n"
            )
        return (
            f"OgunScan Shield — NEW {finding.severity.value} finding\n"
            f"\n"
            f"Rule:        {finding.rule_id} — {finding.title}\n"
            f"Severity:    {finding.severity.value}\n"
            f"Location:    {finding.location}\n"
            f"Scanned:     {scan_path}\n"
            f"\n"
            f"Description: {finding.description}\n"
            f"\n"
            f"Evidence:    {finding.evidence or '(none)'}\n"
            f"\n"
            f"Fix:         {finding.remediation}\n"
            f"\n"
            f"— OgunScan Shield (https://ogunscan.dev)\n"
        )

    def _html_body(self, finding: Finding, scan_path: str, kind: str) -> str:
        color = SEVERITY_COLOR.get(finding.severity, "#708090")
        if kind == "RESOLVED":
            return (
                f"<html><body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#222;max-width:560px;\">"
                f"<table style=\"width:100%;border-collapse:collapse;margin:24px 0;\">"
                f"<tr><td style=\"background:#2E7D32;color:#fff;padding:10px 14px;font-weight:600;border-radius:4px 4px 0 0;\">✓ RESOLVED · {_h(finding.rule_id)}</td></tr>"
                f"<tr><td style=\"border:1px solid #ddd;border-top:none;padding:16px;border-radius:0 0 4px 4px;\">"
                f"<p style=\"margin:0 0 10px;\"><strong>Location:</strong> <code style=\"background:#f4f4f4;padding:2px 6px;border-radius:3px;\">{_h(finding.location)}</code></p>"
                f"<p style=\"margin:0 0 10px;\"><strong>Scanned:</strong> <code style=\"background:#f4f4f4;padding:2px 6px;border-radius:3px;\">{_h(scan_path)}</code></p>"
                f"<p style=\"margin:18px 0 0;color:#555;font-size:13px;\">The finding is no longer present in the most recent scan.</p>"
                f"</td></tr></table>"
                f"<p style=\"color:#999;font-size:12px;margin-top:24px;\">— OgunScan Shield · <a href=\"https://ogunscan.dev\" style=\"color:#888;\">ogunscan.dev</a></p>"
                f"</body></html>"
            )
        return (
            f"<html><body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#222;max-width:560px;\">"
            f"<table style=\"width:100%;border-collapse:collapse;margin:24px 0;\">"
            f"<tr><td style=\"background:{color};color:{SEVERITY_BADGE_TEXT_COLOR};padding:10px 14px;font-weight:600;border-radius:4px 4px 0 0;\">"
            f"{_h(finding.severity.value)} · {_h(finding.rule_id)} — {_h(finding.title)}</td></tr>"
            f"<tr><td style=\"border:1px solid #ddd;border-top:none;padding:16px;border-radius:0 0 4px 4px;\">"
            f"<p style=\"margin:0 0 10px;\"><strong>Location:</strong> <code style=\"background:#f4f4f4;padding:2px 6px;border-radius:3px;\">{_h(finding.location)}</code></p>"
            f"<p style=\"margin:0 0 10px;\"><strong>Scanned:</strong> <code style=\"background:#f4f4f4;padding:2px 6px;border-radius:3px;\">{_h(scan_path)}</code></p>"
            f"<p style=\"margin:0 0 16px;\">{_h(finding.description)}</p>"
            + (f"<p style=\"margin:0 0 16px;\"><strong>Evidence:</strong> <code style=\"background:#fff7e6;padding:2px 6px;border-radius:3px;color:#7a4500;\">{_h(finding.evidence)}</code></p>" if finding.evidence else "")
            + f"<div style=\"background:#f0f7ff;border-left:3px solid #4682B4;padding:10px 14px;margin-top:16px;\">"
            f"<strong style=\"color:#2c5282;\">Fix:</strong> {_h(finding.remediation)}</div>"
            f"</td></tr></table>"
            f"<p style=\"color:#999;font-size:12px;margin-top:24px;\">— OgunScan Shield · <a href=\"https://ogunscan.dev\" style=\"color:#888;\">ogunscan.dev</a></p>"
            f"</body></html>"
        )

    # ── delivery ─────────────────────────────────────────────────────────

    def _send(self, subject: str, plain: str, html: str) -> None:
        """Compose + send. Catches all exceptions — a flapping mail server
        cannot take down the daemon."""
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.user
        msg["To"] = self.recipient
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")
        try:
            self._smtp_send(msg)
        except Exception:
            # Log via history elsewhere; never raise out of a notifier.
            pass

    def _smtp_send(self, msg: EmailMessage) -> None:
        """Actual network send. Separated for test injection."""
        context = ssl.create_default_context()
        if self.port == 465:
            with smtplib.SMTP_SSL(self.host, self.port, context=context, timeout=15) as s:
                s.login(self.user, self.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.host, self.port, timeout=15) as s:
                s.ehlo()
                s.starttls(context=context)
                s.ehlo()
                s.login(self.user, self.password)
                s.send_message(msg)


def _h(s: str) -> str:
    """Minimal HTML escape — keep emails injection-safe."""
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
