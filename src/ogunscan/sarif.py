"""SARIF 2.1.0 emitter — produces output that GitHub's code-scanning
infrastructure consumes natively (security alerts on PRs, the Security
tab, etc.). Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

`ogunscan scan --sarif` swaps the human / JSON outputs for this format.
GitHub Actions consumers upload it via the
`github/codeql-action/upload-sarif@v3` step.
"""

import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterable, List

from . import __version__
from .models import ScanResult, Severity
from .rules import load_builtin


# Map OGN severities to SARIF result levels. CRITICAL+HIGH = error so
# GitHub's PR-checks fail on them; MEDIUM = warning; LOW = note.
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


def to_sarif(results: Iterable[ScanResult], tool_version: str = None) -> Dict[str, Any]:
    """Convert one or more ScanResults into a SARIF 2.1.0 document.

    Returns a dict suitable for json.dumps(). The same rule catalogue
    (from the bundled builtin or, if loaded by the caller, the
    hot-updated signatures) is emitted under tool.driver.rules so
    GitHub knows the rule metadata for every result reference.
    """
    sigs = load_builtin()
    rules_meta = sigs.get("rules", [])
    tool_version = tool_version or __version__

    sarif_rules = [_rule_definition(r) for r in rules_meta]
    sarif_results: List[Dict[str, Any]] = []
    for r in results:
        for f in r.findings:
            sarif_results.append(_finding_result(f, scan_target=r.target))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OgunScan",
                        "version": tool_version,
                        "informationUri": "https://ogunscan.dev",
                        "rules": sarif_rules,
                    },
                },
                "results": sarif_results,
            }
        ],
    }


# ── internals ────────────────────────────────────────────────────────────


def _rule_definition(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a signature rule dict into a SARIF reportingDescriptor."""
    sev_str = rule.get("severity", "INFO")
    try:
        level = SARIF_LEVEL[Severity(sev_str)]
    except (KeyError, ValueError):
        level = "none"
    return {
        "id": rule.get("id", ""),
        "name": _rule_name(rule.get("id", ""), rule.get("title", "")),
        "shortDescription": {"text": rule.get("title", "")},
        "fullDescription": {"text": rule.get("description", "")},
        "help": {
            "text": rule.get("remediation", ""),
            "markdown": rule.get("remediation", ""),
        },
        "defaultConfiguration": {"level": level},
        "properties": {
            "ogunscan_severity": sev_str,
            "category": rule.get("category", "local"),
        },
    }


def _finding_result(finding, scan_target: str) -> Dict[str, Any]:
    """Convert one Finding into a SARIF result."""
    level = SARIF_LEVEL.get(finding.severity, "none")
    message = finding.description or finding.title
    if finding.evidence:
        message = f"{message}\nEvidence: {finding.evidence}"
    if finding.remediation:
        message = f"{message}\nFix: {finding.remediation}"

    result = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [_location(finding, scan_target)],
        "properties": {
            "ogunscan_severity": finding.severity.value,
            "ogunscan_location": finding.location,
        },
    }
    if finding.evidence:
        result["properties"]["ogunscan_evidence"] = finding.evidence
    return result


def _location(finding, scan_target: str) -> Dict[str, Any]:
    """Best-effort physicalLocation. We point at the scanned file URI;
    remote-scan findings (rule_id starts with OGN-6) point at the URL
    via a `logicalLocations` entry instead since SARIF spec wants
    physical paths under `artifactLocation`."""
    if finding.rule_id.startswith("OGN-6"):
        # Remote endpoint — use logicalLocations only
        return {
            "logicalLocations": [
                {"fullyQualifiedName": finding.location, "kind": "uri"}
            ],
            "message": {"text": f"Remote endpoint: {finding.location}"},
        }
    # Local file finding
    uri = _file_uri(scan_target)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            # We don't track line numbers on findings, so emit region=1
            # as a placeholder — GitHub still highlights the file.
            "region": {"startLine": 1},
        },
        "logicalLocations": [
            {"fullyQualifiedName": finding.location, "kind": "member"}
        ],
    }


def _file_uri(path: str) -> str:
    """file:// URI relative or absolute, GitHub's SARIF consumer expects
    either repo-relative paths OR file:// URIs. We emit file:// for
    portability; GitHub's uploader normalizes to repo-relative when run
    inside actions/checkout."""
    p = Path(path)
    if p.is_absolute():
        return "file://" + urllib.parse.quote(str(p))
    return urllib.parse.quote(str(p))


def _rule_name(rule_id: str, title: str) -> str:
    """SARIF prefers PascalCase rule names. Derive from the title."""
    if not title:
        return rule_id
    # Strip non-alphanumeric, PascalCase the rest
    words = "".join(c if c.isalnum() else " " for c in title).split()
    return "".join(w.capitalize() for w in words) or rule_id
