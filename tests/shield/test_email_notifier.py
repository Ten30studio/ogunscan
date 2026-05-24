"""Tests for EmailNotifier — env-driven config, message construction, send-failure
non-fatal. Live SMTP send is verified separately once DJ provides Gmail creds."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.models import Finding, Severity
from ogunscan.shield.notifiers.email import EmailNotifier, _h


def _f(severity=Severity.CRITICAL, rule="OGN-200", title="OpenAI key leaked", evidence="sk-***"):
    return Finding(
        rule_id=rule, severity=severity, title=title,
        description="A real description that ends up in the body.",
        location="config.json -> env.OPENAI_KEY",
        remediation="Move to env vars or a secrets manager.",
        evidence=evidence,
    )


def _set_env(**kv):
    """Helper: clear OGUNSCAN_SMTP_* env then set requested keys."""
    for k in list(os.environ.keys()):
        if k.startswith("OGUNSCAN_SMTP_") or k == "OGUNSCAN_ALERT_EMAIL":
            del os.environ[k]
    for k, v in kv.items():
        os.environ[k] = v


def test_unconfigured_notifier_is_safe_noop():
    """Calling notify_* on an unconfigured EmailNotifier must NOT raise
    and must NOT attempt any SMTP connection."""
    _set_env()
    n = EmailNotifier()
    assert n.is_configured() is False
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_new(_f(), "/x")
        n.notify_resolved(_f(), "/x")
        n.notify_scan_summary("/x", 1, 0, 2)
        smtp.assert_not_called()


def test_from_env_returns_none_when_unconfigured():
    _set_env()
    assert EmailNotifier.from_env() is None


def test_from_env_returns_instance_when_fully_configured():
    _set_env(
        OGUNSCAN_SMTP_HOST="smtp.gmail.com",
        OGUNSCAN_SMTP_PORT="587",
        OGUNSCAN_SMTP_USER="admin@ten30studio.com",
        OGUNSCAN_SMTP_APP_PASS="abcd efgh ijkl mnop",  # spaces should be stripped
        OGUNSCAN_ALERT_EMAIL="admin@ten30studio.com",
    )
    n = EmailNotifier.from_env()
    assert n is not None
    assert n.is_configured()
    assert n.host == "smtp.gmail.com"
    assert n.port == 587
    assert n.password == "abcdefghijklmnop"  # spaces stripped


def test_partial_env_is_not_configured():
    """Missing any required field disables the notifier — no silent partial sends."""
    _set_env(
        OGUNSCAN_SMTP_HOST="smtp.gmail.com",
        OGUNSCAN_SMTP_PORT="587",
        OGUNSCAN_SMTP_USER="admin@ten30studio.com",
        # OGUNSCAN_SMTP_APP_PASS missing
    )
    n = EmailNotifier()
    assert not n.is_configured()


def test_notify_new_sends_with_correct_shape():
    n = EmailNotifier(
        host="smtp.test", port=587, user="from@test.com",
        password="pw", recipient="to@test.com",
    )
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_new(_f(severity=Severity.CRITICAL, rule="OGN-200"), "/abs/config.json")
        smtp.assert_called_once()
        msg = smtp.call_args[0][0]
        # Subject + addresses
        assert "CRITICAL" in msg["Subject"]
        assert "OGN-200" in msg["Subject"]
        assert msg["From"] == "from@test.com"
        assert msg["To"] == "to@test.com"
        # Multipart with plain + html
        payloads = msg.get_payload()
        assert len(payloads) == 2
        types = {p.get_content_type() for p in payloads}
        assert types == {"text/plain", "text/html"}


def test_notify_new_plain_body_contains_all_finding_fields():
    n = EmailNotifier(host="h", port=587, user="u", password="p", recipient="r")
    f = _f()
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_new(f, "/abs/config.json")
        msg = smtp.call_args[0][0]
        plain = next(p for p in msg.get_payload() if p.get_content_type() == "text/plain")
        body = plain.get_content()
        assert "OGN-200" in body
        assert "OpenAI key leaked" in body
        assert "config.json -> env.OPENAI_KEY" in body
        assert "/abs/config.json" in body
        assert "Move to env vars" in body
        assert "sk-***" in body


def test_notify_new_html_body_has_severity_color():
    n = EmailNotifier(host="h", port=587, user="u", password="p", recipient="r")
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_new(_f(severity=Severity.CRITICAL), "/x")
        msg = smtp.call_args[0][0]
        html = next(p for p in msg.get_payload() if p.get_content_type() == "text/html")
        body = html.get_content()
        assert "#B22222" in body  # firebrick for CRITICAL
        assert "<html>" in body
        assert "</html>" in body


def test_notify_resolved_subject_says_resolved():
    n = EmailNotifier(host="h", port=587, user="u", password="p", recipient="r")
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_resolved(_f(), "/x")
        msg = smtp.call_args[0][0]
        assert "RESOLVED" in msg["Subject"]


def test_notify_scan_summary_is_silent():
    """Per-scan summary email would double-deliver alongside per-finding emails. Skip."""
    n = EmailNotifier(host="h", port=587, user="u", password="p", recipient="r")
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_scan_summary("/x", 5, 1, 3)
        smtp.assert_not_called()


def test_send_failure_is_swallowed():
    """A flapping SMTP server cannot crash the daemon."""
    n = EmailNotifier(host="h", port=587, user="u", password="p", recipient="r")
    with patch.object(n, "_smtp_send", side_effect=ConnectionError("nope")):
        n.notify_new(_f(), "/x")  # MUST NOT raise


def test_html_escape_prevents_injection():
    """A finding with HTML-ish characters must be safely escaped."""
    nasty = _f(title="<script>alert(1)</script>")
    n = EmailNotifier(host="h", port=587, user="u", password="p", recipient="r")
    with patch.object(n, "_smtp_send") as smtp:
        n.notify_new(nasty, "/x")
        msg = smtp.call_args[0][0]
        html = next(p for p in msg.get_payload() if p.get_content_type() == "text/html")
        body = html.get_content()
        assert "<script>" not in body
        assert "&lt;script&gt;" in body


def test_html_escape_helper():
    assert _h("a < b & c > d") == "a &lt; b &amp; c &gt; d"
    assert _h('"quoted"') == "&quot;quoted&quot;"
    assert _h("it's") == "it&#39;s"
    assert _h(None) == ""


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
