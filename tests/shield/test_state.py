"""Tests for shield/state.py — registration + atomic persistence + finding round-trip."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.models import Finding, Severity
from ogunscan.shield import state as S


def _scratch():
    return tempfile.TemporaryDirectory()


def _f(rule_id="OGN-200", location="x"):
    return Finding(
        rule_id=rule_id, severity=Severity.CRITICAL, title="t", description="d",
        location=location, remediation="r", evidence="ev",
    )


def test_empty_state_shape():
    s = S.empty_state()
    assert s["schema_version"] == S.SCHEMA_VERSION
    assert s["registered_paths"] == []
    assert s["findings_by_path"] == {}
    assert s["scan_count"] == 0


def test_load_missing_file_returns_empty():
    with _scratch() as tmp:
        path = Path(tmp) / "state.json"
        s = S.load_state(path)
        assert s == S.empty_state()


def test_load_corrupt_file_returns_empty():
    with _scratch() as tmp:
        path = Path(tmp) / "state.json"
        path.write_text("{this is not json", encoding="utf-8")
        s = S.load_state(path)
        assert s == S.empty_state()


def test_load_wrong_schema_returns_empty():
    with _scratch() as tmp:
        path = Path(tmp) / "state.json"
        path.write_text(json.dumps({"schema_version": 999, "registered_paths": ["x"]}), encoding="utf-8")
        s = S.load_state(path)
        assert s == S.empty_state()


def test_save_then_load_roundtrip():
    with _scratch() as tmp:
        path = Path(tmp) / "state.json"
        s = S.empty_state()
        S.register_path(s, "/abs/path/a.json")
        S.set_findings(s, "/abs/path/a.json", [_f("OGN-200", "loc1"), _f("OGN-101", "loc2")])
        S.save_state(s, path)
        loaded = S.load_state(path)
        assert loaded["registered_paths"] == ["/abs/path/a.json"]
        findings = S.get_findings(loaded, "/abs/path/a.json")
        assert len(findings) == 2
        ids = {f.rule_id for f in findings}
        assert ids == {"OGN-200", "OGN-101"}


def test_register_path_idempotent():
    s = S.empty_state()
    assert S.register_path(s, "/a") is True
    assert S.register_path(s, "/a") is False
    assert s["registered_paths"] == ["/a"]


def test_unregister_returns_false_for_unknown():
    s = S.empty_state()
    assert S.unregister_path(s, "/never-added") is False


def test_unregister_drops_findings():
    s = S.empty_state()
    S.register_path(s, "/a")
    S.set_findings(s, "/a", [_f()])
    assert "/a" in s["findings_by_path"]
    S.unregister_path(s, "/a")
    assert "/a" not in s["findings_by_path"]


def test_atomic_write_no_partial_file():
    """If save_state were not atomic, a parallel reader could observe an
    incomplete JSON. Verify the final file is always valid JSON even after
    many saves."""
    with _scratch() as tmp:
        path = Path(tmp) / "state.json"
        s = S.empty_state()
        for i in range(20):
            S.register_path(s, f"/p{i}")
            S.save_state(s, path)
            # Re-read and parse on every iteration — never see a partial write
            loaded = S.load_state(path)
            assert len(loaded["registered_paths"]) == i + 1


def test_mark_scan_complete_updates_fields():
    from datetime import datetime, timedelta, timezone
    s = S.empty_state()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later = now + timedelta(hours=6)
    S.mark_scan_complete(s, now, later)
    assert s["last_scan_at"] == "2026-01-01T00:00:00Z"
    assert s["next_scan_at"] == "2026-01-01T06:00:00Z"
    assert s["scan_count"] == 1
    S.mark_scan_complete(s, now, later)
    assert s["scan_count"] == 2


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
