#!/usr/bin/env python3
"""
OgunScan — MCP Server Security Scanner
Built by Ten30 Studios. Named for Ogun, Yoruba orisha of iron and protection.
"""

import json
import re
import sys
import os
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    remediation: str
    evidence: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    scanned_servers: int = 0
    scanned_tools: int = 0

    @property
    def critical(self):
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self):
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self):
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low(self):
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def passed(self):
        return len(self.findings) == 0


# ── Credential patterns ──────────────────────────────────────────────────────

CREDENTIAL_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{32,}', 'OpenAI API key'),
    (r'sk-ant-[a-zA-Z0-9\-]{32,}', 'Anthropic API key'),
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API key'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub personal access token'),
    (r'ghs_[a-zA-Z0-9]{36}', 'GitHub Actions token'),
    (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', 'Slack bot token'),
    (r'xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{32}', 'Slack user token'),
    (r'AKIA[0-9A-Z]{16}', 'AWS access key ID'),
    (r'(?i)(password|passwd|secret|token|api_key|apikey)\s*[:=]\s*["\']?([^\s"\']{8,})', 'Hardcoded credential'),
    (r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}', 'Bearer token in config'),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private key material'),
]

# ── Prompt injection patterns ─────────────────────────────────────────────────

INJECTION_PATTERNS = [
    (r'ignore (?:previous|all|prior) instructions?', 'Ignore-previous-instructions injection'),
    (r'you are now', 'Role override injection'),
    (r'disregard (?:all|your|the) (?:previous|prior|above)', 'Disregard injection'),
    (r'act as (?:a|an|the)\s+\w+\s+(?:without|that|who)', 'Act-as injection'),
    (r'do not (?:reveal|tell|show|mention|disclose)', 'Information suppression directive'),
    (r'system\s*:\s*you', 'Embedded system prompt'),
    (r'<\|(?:im_start|system|user|assistant)\|>', 'ChatML injection tokens'),
    (r'\[INST\]|\[/INST\]', 'Llama instruction injection tokens'),
    (r'###\s*(?:instruction|system|context)s?', 'Markdown-wrapped system prompt'),
    (r'exfiltrate|extract (?:all|the|user|secret)', 'Data exfiltration directive'),
]

# ── Malicious URL patterns ────────────────────────────────────────────────────

SUSPICIOUS_URL_PATTERNS = [
    (r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', 'Direct IP URL (no hostname)'),
    (r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)', 'Localhost URL in server config'),
    (r'https?://[^/]+\.(?:tk|ml|ga|cf|gq)/', 'Free TLD (high-abuse domain)'),
    (r'ngrok\.io|ngrok\.app', 'Ngrok tunnel URL (ephemeral, unverified)'),
    (r'trycloudflare\.com', 'Cloudflare tunnel URL'),
    (r'\.onion', 'Tor hidden service URL'),
]

# ── Scope / permission checks ─────────────────────────────────────────────────

DANGEROUS_PERMISSIONS = [
    'execute_code',
    'shell_exec',
    'file_write',
    'file_delete',
    'network_unrestricted',
    'admin',
    'sudo',
    'root',
]


class OgunScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def scan_file(self, path: Path) -> ScanResult:
        result = ScanResult(target=str(path))

        try:
            raw = path.read_text(encoding='utf-8')
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            result.findings.append(Finding(
                rule_id='OGN-000',
                severity=Severity.INFO,
                title='Invalid JSON',
                description=f'File could not be parsed as JSON: {e}',
                location=str(path),
                remediation='Ensure the config file is valid JSON.',
            ))
            return result
        except Exception as e:
            result.findings.append(Finding(
                rule_id='OGN-001',
                severity=Severity.INFO,
                title='File read error',
                description=str(e),
                location=str(path),
                remediation='Ensure the file is readable.',
            ))
            return result

        # Detect config format
        servers = self._extract_servers(data)
        result.scanned_servers = len(servers)

        for server_name, server_cfg in servers.items():
            self._check_server(server_name, server_cfg, raw, result, str(path))

        # Full-file credential scan
        self._check_credentials_in_raw(raw, str(path), result)

        return result

    def _extract_servers(self, data: dict) -> dict:
        """Extract MCP server configs from various config formats."""
        # Claude Desktop / Cursor format: {"mcpServers": {...}}
        if 'mcpServers' in data:
            return data['mcpServers']
        # Direct server map
        if 'servers' in data and isinstance(data['servers'], dict):
            return data['servers']
        # Single server
        if 'command' in data or 'url' in data:
            return {'(root)': data}
        return {}

    def _check_server(self, name: str, cfg: dict, raw: str, result: ScanResult, path: str):
        location = f"{path} → server '{name}'"

        # OGN-100: URL checks
        url = cfg.get('url', '')
        if url:
            for pattern, label in SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    result.findings.append(Finding(
                        rule_id='OGN-100',
                        severity=Severity.HIGH,
                        title=f'Suspicious server URL: {label}',
                        description=f"Server '{name}' uses a URL matching a suspicious pattern: {label}",
                        location=location,
                        remediation='Use only verified, stable hostnames for MCP server URLs. Avoid IPs, free TLDs, and tunnel services.',
                        evidence=url[:120],
                    ))

        # OGN-101: HTTP (not HTTPS) remote server
        if url and url.startswith('http://') and not any(x in url for x in ['localhost', '127.0.0.1']):
            result.findings.append(Finding(
                rule_id='OGN-101',
                severity=Severity.CRITICAL,
                title='Unencrypted remote MCP server (HTTP)',
                description=f"Server '{name}' uses HTTP. All traffic including tool calls and responses is unencrypted.",
                location=location,
                remediation='Switch to HTTPS. Never use HTTP for remote MCP servers.',
                evidence=url[:120],
            ))

        # OGN-200: Credential check in env vars
        env = cfg.get('env', {})
        for key, val in env.items():
            if not isinstance(val, str):
                continue
            for pattern, label in CREDENTIAL_PATTERNS:
                if re.search(pattern, val, re.IGNORECASE):
                    result.findings.append(Finding(
                        rule_id='OGN-200',
                        severity=Severity.CRITICAL,
                        title=f'Hardcoded credential in env: {label}',
                        description=f"Server '{name}' has a hardcoded {label} in its env config.",
                        location=f"{location} → env.{key}",
                        remediation='Move credentials to environment variables or a secrets manager. Never hardcode tokens in MCP config files.',
                        evidence=f"{key}: {val[:8]}***",
                    ))
                    break

        # OGN-201: API keys in command args
        args = cfg.get('args', [])
        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                continue
            for pattern, label in CREDENTIAL_PATTERNS:
                if re.search(pattern, arg):
                    result.findings.append(Finding(
                        rule_id='OGN-201',
                        severity=Severity.CRITICAL,
                        title=f'Credential in command args: {label}',
                        description=f"Server '{name}' passes a {label} as a command-line argument. Visible in process listings.",
                        location=f"{location} → args[{i}]",
                        remediation='Use environment variables instead of command-line arguments for credentials.',
                        evidence=arg[:8] + '***',
                    ))

        # OGN-300: Tool description injection
        tools = cfg.get('tools', [])
        result.scanned_tools += len(tools)
        for tool in tools:
            desc = tool.get('description', '') + ' ' + str(tool.get('inputSchema', ''))
            for pattern, label in INJECTION_PATTERNS:
                if re.search(pattern, desc, re.IGNORECASE):
                    result.findings.append(Finding(
                        rule_id='OGN-300',
                        severity=Severity.CRITICAL,
                        title=f'Prompt injection in tool description: {label}',
                        description=f"Tool '{tool.get('name', '?')}' in server '{name}' contains a prompt injection pattern: {label}",
                        location=f"{location} → tools.{tool.get('name', '?')}",
                        remediation='Audit tool descriptions for injected instructions. Only use MCP servers from trusted sources.',
                        evidence=desc[:200],
                    ))
                    break

        # OGN-400: Dangerous permissions/scopes
        perms = cfg.get('permissions', cfg.get('scopes', cfg.get('capabilities', [])))
        if isinstance(perms, list):
            for perm in perms:
                if str(perm).lower() in DANGEROUS_PERMISSIONS:
                    result.findings.append(Finding(
                        rule_id='OGN-400',
                        severity=Severity.HIGH,
                        title=f'Dangerous permission granted: {perm}',
                        description=f"Server '{name}' requests the '{perm}' permission. This is a high-risk capability.",
                        location=f"{location} → permissions",
                        remediation='Apply least-privilege. Only grant permissions explicitly required by the server.',
                        evidence=str(perms),
                    ))

        # OGN-500: Unverified server origin (no url, no checksum)
        if not url and cfg.get('command'):
            cmd = cfg.get('command', '')
            if 'npx' in cmd or 'uvx' in cmd or 'pip' in cmd:
                result.findings.append(Finding(
                    rule_id='OGN-500',
                    severity=Severity.MEDIUM,
                    title='Unverified package-sourced server',
                    description=f"Server '{name}' uses '{cmd}' without a pinned version or checksum. Supply chain attacks can inject malicious code.",
                    location=location,
                    remediation='Pin exact package versions (e.g., npx package@1.2.3). Verify checksums. Review package source before use.',
                    evidence=cmd,
                ))

    def _check_credentials_in_raw(self, raw: str, path: str, result: ScanResult):
        """Scan the full raw file for credential patterns not caught in structured parsing."""
        for pattern, label in CREDENTIAL_PATTERNS[:8]:  # first 8 are regex token patterns
            matches = re.finditer(pattern, raw)
            for match in matches:
                evidence = match.group(0)
                # Skip if already reported
                already = any(
                    f.rule_id in ('OGN-200', 'OGN-201') and evidence[:8] in (f.evidence or '')
                    for f in result.findings
                )
                if not already:
                    result.findings.append(Finding(
                        rule_id='OGN-202',
                        severity=Severity.CRITICAL,
                        title=f'Credential pattern detected: {label}',
                        description=f'A {label} pattern was found in the config file.',
                        location=path,
                        remediation='Remove credentials from config files. Use environment variables or a secrets manager.',
                        evidence=evidence[:8] + '***',
                    ))


def format_report(result: ScanResult, color: bool = True) -> str:
    RED = '\033[91m' if color else ''
    YELLOW = '\033[93m' if color else ''
    GREEN = '\033[92m' if color else ''
    CYAN = '\033[96m' if color else ''
    BOLD = '\033[1m' if color else ''
    RESET = '\033[0m' if color else ''

    lines = []
    lines.append(f"\n{BOLD}⚔️  OgunScan — MCP Security Report{RESET}")
    lines.append(f"   Target: {result.target}")
    lines.append(f"   Servers: {result.scanned_servers} | Tools: {result.scanned_tools}")
    lines.append(f"   Findings: {len(result.findings)} total")
    lines.append('')

    if result.passed:
        lines.append(f"{GREEN}{BOLD}   ✅ PASSED — No vulnerabilities found.{RESET}")
        lines.append('')
        return '\n'.join(lines)

    # Summary bar
    c = len(result.critical)
    h = len(result.high)
    m = len(result.medium)
    l = len(result.low)
    lines.append(f"   {RED}CRITICAL: {c}{RESET}  {YELLOW}HIGH: {h}{RESET}  MEDIUM: {m}  LOW: {l}")
    lines.append('')

    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in sev_order:
        findings = [f for f in result.findings if f.severity == sev]
        if not findings:
            continue

        color_code = RED if sev in (Severity.CRITICAL, Severity.HIGH) else YELLOW if sev == Severity.MEDIUM else ''
        for f in findings:
            lines.append(f"   {color_code}{BOLD}[{f.severity.value}] {f.rule_id} — {f.title}{RESET}")
            lines.append(f"   Location: {f.location}")
            lines.append(f"   {f.description}")
            if f.evidence:
                lines.append(f"   Evidence: {CYAN}{f.evidence}{RESET}")
            lines.append(f"   Fix: {f.remediation}")
            lines.append('')

    return '\n'.join(lines)


__version__ = '0.1.1'

# Rule catalogue (kept here as the single source of truth for `ogunscan rules`)
RULES = [
    ('OGN-100', Severity.HIGH,     'Suspicious server URL',          'IPs, ngrok/tunnel hosts, free-TLD or .onion in server URL'),
    ('OGN-101', Severity.CRITICAL, 'Unencrypted remote server',      'Remote MCP server using HTTP instead of HTTPS'),
    ('OGN-200', Severity.CRITICAL, 'Hardcoded credential in env',    'API key / token / private-key material in server env config'),
    ('OGN-201', Severity.CRITICAL, 'Credential in command args',     'Token passed via CLI args — visible in process listings'),
    ('OGN-202', Severity.CRITICAL, 'Credential pattern in file',     'Token pattern detected in raw config file outside structured fields'),
    ('OGN-300', Severity.CRITICAL, 'Prompt injection in tool desc',  'Injection patterns in tool descriptions hijack agent behavior'),
    ('OGN-400', Severity.HIGH,     'Dangerous permission granted',   'Server requests a high-risk capability (shell_exec, admin, sudo, …)'),
    ('OGN-500', Severity.MEDIUM,   'Unverified package server',      'Unpinned npx/uvx/pip command — supply-chain attack surface'),
]

AUTO_DETECT_PATHS = [
    Path.home() / 'Library/Application Support/Claude/claude_desktop_config.json',
    Path.home() / '.cursor/mcp.json',
    Path.home() / '.config/mcp/config.json',
    Path('mcp.json'),
    Path('.mcp/config.json'),
]


def _resolve_targets(positional, recursive):
    """Turn user-supplied positional args into a flat list of files to scan."""
    out = []
    for raw in positional:
        p = Path(raw)
        if not p.exists():
            print(f'File not found: {p}', file=sys.stderr)
            continue
        if p.is_dir():
            pattern = '**/*.json' if recursive else '*.json'
            out.extend(sorted(p.glob(pattern)))
        else:
            out.append(p)
    return out


def cmd_scan(args):
    scanner = OgunScanner()
    color = not args.no_color and sys.stdout.isatty()
    ignore = set(args.ignore or [])

    targets = _resolve_targets(args.targets, args.recursive) if args.targets else []
    if not targets:
        targets = [p for p in AUTO_DETECT_PATHS if p.exists()]
        if not targets:
            print('No MCP config files found. Specify a file: ogunscan scan <path>', file=sys.stderr)
            sys.exit(0)

    all_results = []
    exit_code = 0

    for target in targets:
        result = scanner.scan_file(target)
        if ignore:
            result.findings = [f for f in result.findings if f.rule_id not in ignore]
        all_results.append(result)
        if result.critical or result.high:
            exit_code = 1
        if not args.json:
            print(format_report(result, color=color))

    if args.json:
        import dataclasses

        def to_dict(obj):
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return {f.name: to_dict(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, list):
                return [to_dict(i) for i in obj]
            if isinstance(obj, dict):
                return {k: to_dict(v) for k, v in obj.items()}
            return obj

        print(json.dumps([to_dict(r) for r in all_results], indent=2))

    sys.exit(exit_code)


def cmd_rules(args):
    print(f"\n⚔️  OgunScan — {len(RULES)} detection rules\n")
    for rule_id, sev, title, desc in RULES:
        print(f"  [{sev.value:8}] {rule_id} — {title}")
        print(f"             {desc}\n")


def cmd_version(args):
    print(f'OgunScan {__version__}')


def cli():
    # Smart verb fallback: `ogunscan path.json` → `ogunscan scan path.json`.
    KNOWN_VERBS = {'scan', 'rules', 'version', '-h', '--help', '--version'}
    argv = sys.argv[1:]
    if argv and argv[0] not in KNOWN_VERBS and not argv[0].startswith('-'):
        argv = ['scan'] + argv
    elif not argv:
        argv = ['scan']

    parser = argparse.ArgumentParser(
        prog='ogunscan',
        description='⚔️  OgunScan — MCP Server Security Scanner by Ten30 Studio',
        epilog='Docs: https://ogunscan.dev/docs · Issues: https://github.com/Ten30studio/ogunscan/issues',
    )
    parser.add_argument('--version', action='version', version=f'OgunScan {__version__}')
    sub = parser.add_subparsers(dest='cmd', required=True, metavar='<command>')

    p_scan = sub.add_parser('scan', help='Scan an MCP config file or directory')
    p_scan.add_argument('targets', nargs='*', help='Config file(s) or directory. Empty = auto-detect.')
    p_scan.add_argument('-r', '--recursive', action='store_true', help='Recurse into directories')
    p_scan.add_argument('-j', '--json', action='store_true', help='Emit JSON instead of human report')
    p_scan.add_argument('--ignore', action='append', metavar='RULE',
                        help='Suppress a rule ID (repeatable, e.g. --ignore OGN-500)')
    p_scan.add_argument('--no-color', action='store_true', help='Disable color output')
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser('rules', help='List all detection rules')
    p_rules.set_defaults(func=cmd_rules)

    p_version = sub.add_parser('version', help='Print version')
    p_version.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    cli()
