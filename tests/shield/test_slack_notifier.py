"""Tests for SlackNotifier — env-driven config, Block Kit payload shape,
network failure non-fatal. Live webhook POST verified separately once DJ
provides the webhook URL."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.models import Finding, Severity
from ogunscan.shield.notifiers.slack import SlackNotifier


def _f(severity=Severity.CRITICAL, rule="OGN-200", title="OpenAI key leaked", evidence="sk-***"):
    return Finding(
        rule_id=rule, severity=severity, title=title,
        description="A real description that ends up in the body.",
        location="config.json -> env.OPENAI_KEY",
        remediation="Move to env vars.",
        evidence=evidence,
    )


def _set_env(value=None):
    if "OGUNSCAN_SLACK_WEBHOOK" in os.environ:
        del os.environ["OGUNSCAN_SLACK_WEBHOOK"]
    if value:
        os.environ["OGUNSCAN_SLACK_WEBHOOK"] = value


def test_unconfigured_is_safe_noop():
    _set_env()
    n = SlackNotifier()
    assert not n.is_configured()
    with patch.object(n, "_do_post") as post:
        n.notify_new(_f(), "/x")
        n.notify_resolved(_f(), "/x")
        n.notify_scan_summary("/x", 1, 0, 2)
        post.assert_not_called()


def test_from_env_returns_none_when_unset():
    _set_env()
    assert SlackNotifier.from_env() is None


def test_from_env_rejects_non_slack_url():
    """Defensive: only accept hooks.slack.com URLs. Catches misconfigured webhooks
    (someone pasting a Discord webhook URL into the Slack slot, etc.)."""
    _set_env("https://example.com/webhook")
    assert SlackNotifier.from_env() is None


def test_from_env_accepts_valid_slack_url():
    _set_env("https://hooks.slack.com/services/T123/B456/abcdef")
    n = SlackNotifier.from_env()
    assert n is not None
    assert n.is_configured()


def test_notify_new_payload_has_correct_shape():
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    with patch.object(n, "_do_post") as post:
        n.notify_new(_f(severity=Severity.CRITICAL, rule="OGN-200"), "/abs/config.json")
        post.assert_called_once()
        payload = post.call_args[0][0]
        # Top-level fallback text
        assert "CRITICAL" in payload["text"]
        assert "OGN-200" in payload["text"]
        # Single attachment with severity color bar
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1
        att = payload["attachments"][0]
        assert att["color"] == "#B22222"  # CRITICAL color
        # Block Kit blocks
        blocks = att["blocks"]
        block_text = json.dumps(blocks)
        assert "OGN-200" in block_text
        assert "OpenAI key leaked" in block_text
        assert "config.json -> env.OPENAI_KEY" in block_text
        assert "/abs/config.json" in block_text
        assert "Move to env vars" in block_text
        assert "sk-***" in block_text


def test_severity_colors_differ_by_level():
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    levels_seen = {}
    with patch.object(n, "_do_post") as post:
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            n.notify_new(_f(severity=sev), "/x")
        for call in post.call_args_list:
            payload = call[0][0]
            color = payload["attachments"][0]["color"]
            levels_seen[color] = levels_seen.get(color, 0) + 1
    # Four distinct colors used
    assert len(levels_seen) == 4


def test_notify_new_without_evidence_omits_evidence_block():
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    f = _f(evidence=None)
    with patch.object(n, "_do_post") as post:
        n.notify_new(f, "/x")
        payload = post.call_args[0][0]
        block_text = json.dumps(payload["attachments"][0]["blocks"])
        assert "Evidence" not in block_text


def test_notify_resolved_payload():
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    with patch.object(n, "_do_post") as post:
        n.notify_resolved(_f(rule="OGN-200"), "/x")
        payload = post.call_args[0][0]
        assert "RESOLVED" in payload["text"]
        assert payload["attachments"][0]["color"] == "#2E7D32"  # green
        block_text = json.dumps(payload["attachments"][0]["blocks"])
        assert "OGN-200" in block_text


def test_notify_scan_summary_is_silent():
    """Skip per-scan summary to avoid channel noise — per-finding messages suffice."""
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    with patch.object(n, "_do_post") as post:
        n.notify_scan_summary("/x", 5, 1, 3)
        post.assert_not_called()


def test_post_failure_is_swallowed():
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    with patch.object(n, "_do_post", side_effect=ConnectionError("nope")):
        n.notify_new(_f(), "/x")  # MUST NOT raise


def test_non_200_response_raises_internally_but_caller_doesnt_see():
    """If Slack returns a non-200, _do_post raises IOError but _post swallows it.
    Verifies our two-layer error containment."""
    n = SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/abc")
    class _Resp:
        status = 500
        def __enter__(self): return self
        def __exit__(self, *a): return False
    with patch("urllib.request.urlopen", return_value=_Resp()):
        n.notify_new(_f(), "/x")  # MUST NOT raise


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
            print(f"  💥 {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
