"""Tests for diff_findings — the foundation of Shield's 'fire on new finding' alert logic."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ogunscan.models import Finding, Severity
from ogunscan.diff import diff_findings, FindingDiff


def _f(rule_id: str, location: str, evidence: str = "") -> Finding:
    """Test helper — build a Finding with just the fields diff cares about."""
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        title="test",
        description="test",
        location=location,
        remediation="test",
        evidence=evidence,
    )


def test_first_scan_all_new():
    """Empty previous → everything in current is new. Shield's first-run behavior."""
    current = [_f("OGN-200", "config.json → env.X"), _f("OGN-101", "config.json")]
    d = diff_findings([], current)
    assert len(d.new) == 2
    assert len(d.resolved) == 0
    assert len(d.unchanged) == 0


def test_no_change():
    """Same findings in both scans → all unchanged."""
    findings = [_f("OGN-200", "a"), _f("OGN-101", "b")]
    d = diff_findings(findings, findings)
    assert len(d.new) == 0
    assert len(d.resolved) == 0
    assert len(d.unchanged) == 2


def test_new_finding_detected():
    """Adding a finding shows up as new; existing stays unchanged."""
    prev = [_f("OGN-200", "a")]
    curr = [_f("OGN-200", "a"), _f("OGN-101", "b")]
    d = diff_findings(prev, curr)
    assert len(d.new) == 1
    assert d.new[0].rule_id == "OGN-101"
    assert len(d.unchanged) == 1
    assert d.unchanged[0].rule_id == "OGN-200"
    assert len(d.resolved) == 0


def test_resolved_finding_detected():
    """Removing a finding shows up as resolved."""
    prev = [_f("OGN-200", "a"), _f("OGN-101", "b")]
    curr = [_f("OGN-200", "a")]
    d = diff_findings(prev, curr)
    assert len(d.new) == 0
    assert len(d.unchanged) == 1
    assert len(d.resolved) == 1
    assert d.resolved[0].rule_id == "OGN-101"


def test_identity_uses_rule_id_and_location():
    """Same rule_id at a different location = different finding (new + resolved)."""
    prev = [_f("OGN-200", "config.json → env.OLD")]
    curr = [_f("OGN-200", "config.json → env.NEW")]
    d = diff_findings(prev, curr)
    assert len(d.new) == 1
    assert len(d.resolved) == 1
    assert len(d.unchanged) == 0


def test_evidence_change_at_same_location_is_unchanged():
    """If rule_id + location match but evidence text differs (e.g. token rotated),
    it's still 'the same finding' for diff purposes. Evidence change alone
    shouldn't spam alerts."""
    prev = [_f("OGN-200", "a", evidence="sk-old***")]
    curr = [_f("OGN-200", "a", evidence="sk-new***")]
    d = diff_findings(prev, curr)
    assert len(d.unchanged) == 1
    assert len(d.new) == 0
    assert len(d.resolved) == 0


def test_empty_to_empty():
    """No findings, no change. Shield's steady-state happy path."""
    d = diff_findings([], [])
    assert len(d.new) == 0
    assert len(d.resolved) == 0
    assert len(d.unchanged) == 0


def test_total_replacement():
    """Every old finding resolved, every new finding new. Edge of the spectrum."""
    prev = [_f("OGN-200", "a"), _f("OGN-101", "b")]
    curr = [_f("OGN-300", "c"), _f("OGN-500", "d")]
    d = diff_findings(prev, curr)
    assert len(d.new) == 2
    assert len(d.resolved) == 2
    assert len(d.unchanged) == 0


def test_diff_is_a_named_tuple():
    """API guarantee: callers can unpack (new, resolved, unchanged)."""
    d = diff_findings([], [_f("OGN-200", "a")])
    new, resolved, unchanged = d
    assert new == d.new
    assert resolved == d.resolved
    assert unchanged == d.unchanged
    assert isinstance(d, FindingDiff)


if __name__ == "__main__":
    tests = [
        test_first_scan_all_new,
        test_no_change,
        test_new_finding_detected,
        test_resolved_finding_detected,
        test_identity_uses_rule_id_and_location,
        test_evidence_change_at_same_location_is_unchanged,
        test_empty_to_empty,
        test_total_replacement,
        test_diff_is_a_named_tuple,
    ]
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
