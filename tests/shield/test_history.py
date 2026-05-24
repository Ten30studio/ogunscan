"""Tests for shield/history.py — append-only JSONL + tail."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.shield import history as H


def _scratch_home():
    """TemporaryDirectory + env override so history writes land in our scratch."""
    tmp = tempfile.TemporaryDirectory()
    os.environ["OGUNSCAN_SHIELD_HOME"] = tmp.name
    return tmp


def test_record_then_tail_returns_event():
    with _scratch_home() as tmp:
        H.record("scan_started", paths=3)
        events = H.tail(10)
        assert len(events) == 1
        assert events[0]["kind"] == "scan_started"
        assert events[0]["paths"] == 3
        assert "ts" in events[0]
    os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_tail_limits_to_n():
    with _scratch_home() as tmp:
        for i in range(15):
            H.record("test_event", i=i)
        last_5 = H.tail(5)
        assert len(last_5) == 5
        # newest at end
        assert last_5[-1]["i"] == 14
        assert last_5[0]["i"] == 10
    os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_tail_with_no_history_returns_empty():
    with _scratch_home() as tmp:
        assert H.tail(10) == []
    os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_record_failure_does_not_raise():
    """History is observability — write failures must never propagate."""
    # Point OGUNSCAN_SHIELD_HOME at a file (not a directory) so mkdir fails
    with tempfile.NamedTemporaryFile() as f:
        os.environ["OGUNSCAN_SHIELD_HOME"] = f.name  # this is a FILE not a dir
        H.record("test_event", x=1)  # MUST NOT raise
    os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_iter_events_yields_in_order():
    with _scratch_home() as tmp:
        for i in range(5):
            H.record("e", i=i)
        events = list(H.iter_events())
        assert len(events) == 5
        for idx, ev in enumerate(events):
            assert ev["i"] == idx
    os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_malformed_line_in_history_is_skipped():
    """A corrupt JSONL line shouldn't crash tail() — skip it."""
    with _scratch_home() as tmp:
        # `tmp` here is the string path (TemporaryDirectory.__enter__ returns .name)
        H.record("good_1", i=1)
        # Manually append a bad line
        from datetime import datetime, timezone
        today_path = Path(tmp) / "history" / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"
        with open(today_path, "a", encoding="utf-8") as fp:
            fp.write("not json at all\n")
        H.record("good_2", i=2)
        events = H.tail(10)
        # Two good events, the bad one filtered out
        assert len(events) == 2
        assert events[0]["i"] == 1
        assert events[1]["i"] == 2
    os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


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
