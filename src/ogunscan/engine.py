"""OgunScan rule engine.

The engine knows HOW to apply each pattern category to an MCP config. The
WHAT (which patterns to look for) lives in signatures data (`rules/builtin.json`
shipped with the package, or hot-updated via Shield from
ogunscan.dev/signatures/latest.json).

This split means signature updates can add new patterns to any existing
category without a code release. Adding a fundamentally new check category
still requires a code update — by design.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Finding, ScanResult, Severity
from .rules import load_builtin


class OgunScanner:
    """Run the OgunScan rule engine against MCP config files.

    Parameters
    ----------
    signatures : dict | None
        Signatures dict (rules + patterns). If None, the bundled builtin is
        loaded. Shield passes a fresher dict pulled from ogunscan.dev.
    verbose : bool
        Reserved for future use.
    """

    def __init__(self, signatures: Optional[Dict[str, Any]] = None, verbose: bool = False):
        self.signatures = signatures if signatures is not None else load_builtin()
        self.verbose = verbose
        # Index rule metadata by id for O(1) lookup when constructing Findings.
        self._rules_by_id = {r["id"]: r for r in self.signatures.get("rules", [])}
        patterns = self.signatures.get("patterns", {})
        self._credentials = patterns.get("credentials", [])
        self._injection = patterns.get("injection", [])
        self._suspicious_urls = patterns.get("suspicious_urls", [])
        self._dangerous_permissions = {
            str(p).lower() for p in patterns.get("dangerous_permissions", [])
        }

    # ── public API ────────────────────────────────────────────────────────

    def scan_file(self, path: Path) -> ScanResult:
        result = ScanResult(target=str(path))

        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            result.findings.append(Finding(
                rule_id="OGN-000",
                severity=Severity.INFO,
                title="Invalid JSON",
                description=f"File could not be parsed as JSON: {e}",
                location=str(path),
                remediation="Ensure the config file is valid JSON.",
            ))
            return result
        except Exception as e:
            result.findings.append(Finding(
                rule_id="OGN-001",
                severity=Severity.INFO,
                title="File read error",
                description=str(e),
                location=str(path),
                remediation="Ensure the file is readable.",
            ))
            return result

        servers = self._extract_servers(data)
        result.scanned_servers = len(servers)

        for server_name, server_cfg in servers.items():
            self._check_server(server_name, server_cfg, raw, result, str(path))

        # Full-file credential scan for any token patterns we missed in the
        # structured pass (e.g. tokens embedded in comments or unfamiliar fields).
        self._check_credentials_in_raw(raw, str(path), result)

        return result

    # ── internals ─────────────────────────────────────────────────────────

    def _extract_servers(self, data: dict) -> dict:
        """Extract MCP server configs from the variant shapes in the wild."""
        if "mcpServers" in data:
            return data["mcpServers"]
        if "servers" in data and isinstance(data["servers"], dict):
            return data["servers"]
        if "command" in data or "url" in data:
            return {"(root)": data}
        return {}

    def _rule_meta(self, rule_id: str) -> Dict[str, Any]:
        """Get rule metadata (severity, title, description, remediation) by id.
        Falls back to safe defaults if the rule isn't in the loaded signatures —
        keeps engine resilient if a signature update goes wrong."""
        meta = self._rules_by_id.get(rule_id, {})
        return {
            "severity": Severity(meta.get("severity", "INFO")),
            "title": meta.get("title", rule_id),
            "description": meta.get("description", ""),
            "remediation": meta.get("remediation", ""),
        }

    def _check_server(self, name: str, cfg: dict, raw: str, result: ScanResult, path: str):
        location = f"{path} → server '{name}'"

        # OGN-100: suspicious URL
        url = cfg.get("url", "")
        if url:
            for entry in self._suspicious_urls:
                pattern, label = entry["regex"], entry["label"]
                if re.search(pattern, url, re.IGNORECASE):
                    m = self._rule_meta("OGN-100")
                    result.findings.append(Finding(
                        rule_id="OGN-100",
                        severity=m["severity"],
                        title=f'{m["title"]}: {label}',
                        description=f"Server '{name}' uses a URL matching a suspicious pattern: {label}",
                        location=location,
                        remediation=m["remediation"],
                        evidence=url[:120],
                    ))

        # OGN-101: HTTP (not HTTPS) remote server
        if url and url.startswith("http://") and not any(x in url for x in ["localhost", "127.0.0.1"]):
            m = self._rule_meta("OGN-101")
            result.findings.append(Finding(
                rule_id="OGN-101",
                severity=m["severity"],
                title="Unencrypted remote MCP server (HTTP)",
                description=f"Server '{name}' uses HTTP. All traffic including tool calls and responses is unencrypted.",
                location=location,
                remediation=m["remediation"],
                evidence=url[:120],
            ))

        # OGN-200: credential in env (IGNORECASE — matches existing v0.1.2 behaviour)
        env = cfg.get("env", {})
        for key, val in env.items():
            if not isinstance(val, str):
                continue
            for entry in self._credentials:
                pattern, label = entry["regex"], entry["label"]
                if re.search(pattern, val, re.IGNORECASE):
                    m = self._rule_meta("OGN-200")
                    result.findings.append(Finding(
                        rule_id="OGN-200",
                        severity=m["severity"],
                        title=f"Hardcoded credential in env: {label}",
                        description=f"Server '{name}' has a hardcoded {label} in its env config.",
                        location=f"{location} → env.{key}",
                        remediation=m["remediation"],
                        evidence=f"{key}: {val[:8]}***",
                    ))
                    break  # one finding per env entry

        # OGN-201: credential in command args (case-sensitive — matches v0.1.2)
        args = cfg.get("args", [])
        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                continue
            for entry in self._credentials:
                pattern, label = entry["regex"], entry["label"]
                if re.search(pattern, arg):
                    m = self._rule_meta("OGN-201")
                    result.findings.append(Finding(
                        rule_id="OGN-201",
                        severity=m["severity"],
                        title=f"Credential in command args: {label}",
                        description=f"Server '{name}' passes a {label} as a command-line argument. Visible in process listings.",
                        location=f"{location} → args[{i}]",
                        remediation=m["remediation"],
                        evidence=arg[:8] + "***",
                    ))

        # OGN-300: prompt injection in tool descriptions / schemas
        tools = cfg.get("tools", [])
        result.scanned_tools += len(tools)
        for tool in tools:
            desc = tool.get("description", "") + " " + str(tool.get("inputSchema", ""))
            for entry in self._injection:
                pattern, label = entry["regex"], entry["label"]
                if re.search(pattern, desc, re.IGNORECASE):
                    m = self._rule_meta("OGN-300")
                    result.findings.append(Finding(
                        rule_id="OGN-300",
                        severity=m["severity"],
                        title=f"Prompt injection in tool description: {label}",
                        description=f"Tool '{tool.get('name', '?')}' in server '{name}' contains a prompt injection pattern: {label}",
                        location=f"{location} → tools.{tool.get('name', '?')}",
                        remediation=m["remediation"],
                        evidence=desc[:200],
                    ))
                    break

        # OGN-400: dangerous permissions
        perms = cfg.get("permissions", cfg.get("scopes", cfg.get("capabilities", [])))
        if isinstance(perms, list):
            for perm in perms:
                if str(perm).lower() in self._dangerous_permissions:
                    m = self._rule_meta("OGN-400")
                    result.findings.append(Finding(
                        rule_id="OGN-400",
                        severity=m["severity"],
                        title=f"Dangerous permission granted: {perm}",
                        description=f"Server '{name}' requests the '{perm}' permission. This is a high-risk capability.",
                        location=f"{location} → permissions",
                        remediation=m["remediation"],
                        evidence=str(perms),
                    ))

        # OGN-500: unverified package source
        if not url and cfg.get("command"):
            cmd = cfg.get("command", "")
            if "npx" in cmd or "uvx" in cmd or "pip" in cmd:
                m = self._rule_meta("OGN-500")
                result.findings.append(Finding(
                    rule_id="OGN-500",
                    severity=m["severity"],
                    title="Unverified package-sourced server",
                    description=f"Server '{name}' uses '{cmd}' without a pinned version or checksum. Supply chain attacks can inject malicious code.",
                    location=location,
                    remediation=m["remediation"],
                    evidence=cmd,
                ))

    def _check_credentials_in_raw(self, raw: str, path: str, result: ScanResult):
        """Raw-file credential scan for any tokens that slipped past the
        structured pass. Only patterns flagged `raw_scan: true` participate —
        contextual patterns (e.g. password=...) generate too many false
        positives outside structured fields."""
        raw_patterns = [p for p in self._credentials if p.get("raw_scan", True)]
        for entry in raw_patterns:
            pattern, label = entry["regex"], entry["label"]
            for match in re.finditer(pattern, raw):
                evidence = match.group(0)
                already = any(
                    f.rule_id in ("OGN-200", "OGN-201") and evidence[:8] in (f.evidence or "")
                    for f in result.findings
                )
                if not already:
                    m = self._rule_meta("OGN-202")
                    result.findings.append(Finding(
                        rule_id="OGN-202",
                        severity=m["severity"],
                        title=f"Credential pattern detected: {label}",
                        description=f"A {label} pattern was found in the config file.",
                        location=path,
                        remediation=m["remediation"],
                        evidence=evidence[:8] + "***",
                    ))
