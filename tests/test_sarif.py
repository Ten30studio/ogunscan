"""Tests for the SARIF emitter — schema shape, severity mapping, rule
definitions, local vs remote location handling."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ogunscan.models import Finding, ScanResult, Severity
from ogunscan.sarif import to_sarif, SARIF_LEVEL


def _f(rule="OGN-200", sev=Severity.CRITICAL, location="config.json -> env.X"):
    return Finding(
        rule_id=rule, severity=sev, title="t", description="d",
        location=location, remediation="r", evidence="ev",
    )


def _r(target="/tmp/config.json", findings=None):
    return ScanResult(target=target, findings=findings or [])


def test_top_level_schema_and_version():
    out = to_sarif([_r()])
    assert out["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert out["version"] == "2.1.0"
    assert isinstance(out["runs"], list)
    assert len(out["runs"]) == 1


def test_tool_driver_metadata():
    out = to_sarif([_r()])
    driver = out["runs"][0]["tool"]["driver"]
    assert driver["name"] == "OgunScan"
    assert driver["informationUri"] == "https://ogunscan.dev"
    assert "version" in driver
    assert isinstance(driver["rules"], list)
    assert len(driver["rules"]) >= 8  # the bundled rules


def test_rule_definitions_have_required_sarif_fields():
    out = to_sarif([_r()])
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    for r in rules:
        assert "id" in r
        assert "name" in r
        assert "shortDescription" in r and "text" in r["shortDescription"]
        assert "fullDescription" in r and "text" in r["fullDescription"]
        assert "defaultConfiguration" in r and "level" in r["defaultConfiguration"]


def test_severity_mapping_critical_to_error():
    assert SARIF_LEVEL[Severity.CRITICAL] == "error"


def test_severity_mapping_high_to_error():
    assert SARIF_LEVEL[Severity.HIGH] == "error"


def test_severity_mapping_medium_to_warning():
    assert SARIF_LEVEL[Severity.MEDIUM] == "warning"


def test_severity_mapping_low_to_note():
    assert SARIF_LEVEL[Severity.LOW] == "note"


def test_finding_emits_result_with_correct_level():
    out = to_sarif([_r(findings=[_f(sev=Severity.CRITICAL), _f(rule="OGN-500", sev=Severity.MEDIUM)])])
    results = out["runs"][0]["results"]
    assert len(results) == 2
    levels = [r["level"] for r in results]
    assert "error" in levels
    assert "warning" in levels


def test_local_finding_uses_physicalLocation():
    """Local-config findings (OGN-100..500) point at a file URI."""
    out = to_sarif([_r(target="/abs/config.json", findings=[_f(rule="OGN-200")])])
    result = out["runs"][0]["results"][0]
    loc = result["locations"][0]
    assert "physicalLocation" in loc
    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
    assert "config.json" in uri


def test_remote_finding_uses_logicalLocations():
    """Remote-endpoint findings (OGN-600..604) use logicalLocations + URL,
    no physicalLocation (there's no file path to point at)."""
    remote_finding = _f(rule="OGN-602", location="https://insecure.example.com/mcp")
    out = to_sarif([_r(target="https://insecure.example.com/mcp", findings=[remote_finding])])
    result = out["runs"][0]["results"][0]
    loc = result["locations"][0]
    assert "physicalLocation" not in loc
    assert "logicalLocations" in loc
    assert loc["logicalLocations"][0]["fullyQualifiedName"] == "https://insecure.example.com/mcp"


def test_result_properties_include_ogunscan_severity():
    """We surface the OGN severity as a custom property so downstream
    consumers can distinguish CRITICAL from HIGH (both = SARIF 'error')."""
    out = to_sarif([_r(findings=[_f(sev=Severity.CRITICAL)])])
    result = out["runs"][0]["results"][0]
    assert result["properties"]["ogunscan_severity"] == "CRITICAL"


def test_message_text_includes_evidence_and_fix():
    out = to_sarif([_r(findings=[_f()])])
    result = out["runs"][0]["results"][0]
    msg = result["message"]["text"]
    assert "ev" in msg or "Evidence:" in msg
    assert "Fix" in msg or "r" in msg


def test_empty_scan_emits_zero_results_but_valid_doc():
    out = to_sarif([])
    assert out["version"] == "2.1.0"
    assert out["runs"][0]["results"] == []
    # Tool driver still emitted with the rule catalogue
    assert len(out["runs"][0]["tool"]["driver"]["rules"]) >= 8


def test_multiple_scan_results_merge_into_one_run():
    """Multiple ScanResults from one scan invocation produce a single SARIF run
    with results aggregated across all targets."""
    r1 = _r(target="/a.json", findings=[_f(rule="OGN-200")])
    r2 = _r(target="/b.json", findings=[_f(rule="OGN-101")])
    out = to_sarif([r1, r2])
    results = out["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"OGN-200", "OGN-101"}


def test_rule_definitions_emit_remote_category_flag():
    """OGN-600 series rules carry category=remote so consumers can filter."""
    out = to_sarif([])
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    remote_rules = [r for r in rules if r.get("properties", {}).get("category") == "remote"]
    assert len(remote_rules) == 5  # OGN-600..604
    ids = {r["id"] for r in remote_rules}
    assert ids == {"OGN-600", "OGN-601", "OGN-602", "OGN-603", "OGN-604"}


def test_serializes_to_valid_json():
    """Spot-check: the SARIF dict roundtrips through json.dumps/loads."""
    out = to_sarif([_r(findings=[_f()])])
    s = json.dumps(out)
    parsed = json.loads(s)
    assert parsed["version"] == "2.1.0"


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
