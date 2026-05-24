"""SlackNotifier — sends Shield alerts to a Slack channel via incoming webhook.

Uses Block Kit so the message renders cleanly in Slack (severity color bar,
header, fields, fix block) and degrades to a usable fallback text when Slack
clients render the notification preview.

Env var:

  OGUNSCAN_SLACK_WEBHOOK    full webhook URL (https://hooks.slack.com/services/T.../B.../...)

Pure stdlib (urllib) so the package keeps `dependencies = []`.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Optional

from ...models import Finding, Severity
from .base import Notifier


# Slack's standard alert color names map to bar colors. We use hex so we
# get consistent rendering regardless of theme.
SEVERITY_COLOR = {
    Severity.CRITICAL: "#B22222",
    Severity.HIGH:     "#D2691E",
    Severity.MEDIUM:   "#B8860B",
    Severity.LOW:      "#4682B4",
    Severity.INFO:     "#708090",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH:     "⚠️",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "ℹ️",
}


class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, webhook_url: Optional[str] = None, timeout: int = 10):
        self.webhook_url = webhook_url or os.environ.get("OGUNSCAN_SLACK_WEBHOOK")
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> Optional["SlackNotifier"]:
        instance = cls()
        return instance if instance.is_configured() else None

    def is_configured(self) -> bool:
        return bool(self.webhook_url and self.webhook_url.startswith("https://hooks.slack.com/"))

    # ── Notifier interface ────────────────────────────────────────────────

    def notify_new(self, finding: Finding, scan_path: str) -> None:
        if not self.is_configured():
            return
        payload = self._build_new_payload(finding, scan_path)
        self._post(payload)

    def notify_resolved(self, finding: Finding, scan_path: str) -> None:
        if not self.is_configured():
            return
        payload = self._build_resolved_payload(finding, scan_path)
        self._post(payload)

    def notify_scan_summary(self, scan_path: str, total_new: int, total_resolved: int, total_unchanged: int) -> None:
        # Skip — per-finding messages cover the surface. Daily-digest variant
        # is a future option (would batch summaries to reduce channel noise).
        return

    # ── payloads ──────────────────────────────────────────────────────────

    def _build_new_payload(self, finding: Finding, scan_path: str) -> dict:
        emoji = SEVERITY_EMOJI.get(finding.severity, "")
        color = SEVERITY_COLOR.get(finding.severity, "#708090")
        fallback_text = f"{emoji} {finding.severity.value} {finding.rule_id} — {finding.title} at {finding.location}"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {finding.severity.value} · {finding.rule_id}", "emoji": True},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{finding.title}*\n{finding.description}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Location*\n`{finding.location}`"},
                    {"type": "mrkdwn", "text": f"*Scanned*\n`{scan_path}`"},
                ],
            },
        ]
        if finding.evidence:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Evidence*\n`{finding.evidence}`"},
            })
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Fix*\n{finding.remediation}"},
        })
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": "OgunScan Shield · <https://ogunscan.dev|ogunscan.dev>"},
            ],
        })

        # `attachments` with a `color` gives us the left-edge color bar that
        # makes severity visually scannable in the channel feed.
        return {
            "text": fallback_text,
            "attachments": [
                {"color": color, "blocks": blocks}
            ],
        }

    def _build_resolved_payload(self, finding: Finding, scan_path: str) -> dict:
        fallback_text = f"✓ RESOLVED {finding.rule_id} at {finding.location}"
        blocks = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"✓ *RESOLVED* · `{finding.rule_id}` at `{finding.location}`"},
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "The finding is no longer present in the most recent scan."},
                ],
            },
        ]
        return {
            "text": fallback_text,
            "attachments": [
                {"color": "#2E7D32", "blocks": blocks}
            ],
        }

    # ── delivery ─────────────────────────────────────────────────────────

    def _post(self, payload: dict) -> None:
        """POST the webhook. Catches all exceptions — Slack hiccups never
        crash the daemon."""
        try:
            self._do_post(payload)
        except Exception:
            pass

    def _do_post(self, payload: dict) -> None:
        """Separated for test injection."""
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "ogunscan-shield/1"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            # Slack returns 200 + "ok" on success; non-200 means something's wrong
            if resp.status != 200:
                raise IOError(f"Slack webhook returned {resp.status}")
