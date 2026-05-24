"""Tests for shield/notifiers — abstract interface contract + StdoutNotifier."""

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.models import Finding, Severity
from ogunscan.shield.notifiers import Notifier, StdoutNotifier, REGISTRY, get, register, list_available


def _f(rule="OGN-200", title="OpenAI key leaked"):
    return Finding(
        rule_id=rule, severity=Severity.CRITICAL, title=title, description="d",
        location="config.json → env.OPENAI_KEY", remediation="rotate it",
        evidence="sk-***",
    )


def test_abstract_notifier_is_safe_noop():
    """Default Notifier methods exist and don't raise — subclasses opt-in."""
    n = Notifier()
    n.notify_new(_f(), "config.json")
    n.notify_resolved(_f(), "config.json")
    n.notify_scan_summary("config.json", 0, 0, 0)


def test_stdout_notifier_writes_new():
    buf = io.StringIO()
    n = StdoutNotifier(stream=buf)
    n.notify_new(_f(), "/abs/config.json")
    out = buf.getvalue()
    assert "NEW" in out
    assert "OGN-200" in out
    assert "OpenAI key leaked" in out
    assert "/abs/config.json" in out
    assert "rotate it" in out


def test_stdout_notifier_writes_resolved():
    buf = io.StringIO()
    n = StdoutNotifier(stream=buf)
    n.notify_resolved(_f(), "/abs/config.json")
    out = buf.getvalue()
    assert "RESOLVED" in out
    assert "OGN-200" in out
    assert "/abs/config.json" in out


def test_stdout_notifier_writes_summary():
    buf = io.StringIO()
    n = StdoutNotifier(stream=buf)
    n.notify_scan_summary("/x", total_new=2, total_resolved=1, total_unchanged=4)
    out = buf.getvalue()
    assert "new:2" in out
    assert "resolved:1" in out
    assert "unchanged:4" in out


def test_stdout_notifier_handles_closed_stream():
    """Write to a closed StringIO — must not raise."""
    buf = io.StringIO()
    n = StdoutNotifier(stream=buf)
    buf.close()
    n.notify_new(_f(), "/x")  # MUST NOT raise


def test_registry_contains_stdout_by_default():
    assert "stdout" in list_available()
    assert get("stdout") is StdoutNotifier


def test_registry_register_new_impl():
    class Dummy(Notifier):
        name = "dummy-test"
    register("dummy-test", Dummy)
    assert "dummy-test" in list_available()
    assert get("dummy-test") is Dummy
    # cleanup so other tests aren't polluted
    REGISTRY.pop("dummy-test", None)


def test_registry_unknown_raises():
    try:
        get("does-not-exist")
        raise AssertionError("expected KeyError")
    except KeyError:
        pass


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
