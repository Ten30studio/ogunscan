"""Human-facing terminal report renderer.

Kept separate from `engine.py` so the engine has zero opinions about
output. CLI calls this; Shield's email/Slack notifiers (Phase 3) use
their own renderers tuned for their channel.
"""

from .models import ScanResult, Severity


def format_report(result: ScanResult, color: bool = True) -> str:
    RED = "\033[91m" if color else ""
    YELLOW = "\033[93m" if color else ""
    GREEN = "\033[92m" if color else ""
    CYAN = "\033[96m" if color else ""
    BOLD = "\033[1m" if color else ""
    RESET = "\033[0m" if color else ""

    lines = []
    lines.append(f"\n{BOLD}⚔️  OgunScan — MCP Security Report{RESET}")
    lines.append(f"   Target: {result.target}")
    lines.append(f"   Servers: {result.scanned_servers} | Tools: {result.scanned_tools}")
    lines.append(f"   Findings: {len(result.findings)} total")
    lines.append("")

    if result.passed:
        lines.append(f"{GREEN}{BOLD}   ✅ PASSED — No vulnerabilities found.{RESET}")
        lines.append("")
        return "\n".join(lines)

    c = len(result.critical)
    h = len(result.high)
    m = len(result.medium)
    l = len(result.low)
    lines.append(f"   {RED}CRITICAL: {c}{RESET}  {YELLOW}HIGH: {h}{RESET}  MEDIUM: {m}  LOW: {l}")
    lines.append("")

    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in sev_order:
        findings = [f for f in result.findings if f.severity == sev]
        if not findings:
            continue
        color_code = RED if sev in (Severity.CRITICAL, Severity.HIGH) else YELLOW if sev == Severity.MEDIUM else ""
        for f in findings:
            lines.append(f"   {color_code}{BOLD}[{f.severity.value}] {f.rule_id} — {f.title}{RESET}")
            lines.append(f"   Location: {f.location}")
            lines.append(f"   {f.description}")
            if f.evidence:
                lines.append(f"   Evidence: {CYAN}{f.evidence}{RESET}")
            lines.append(f"   Fix: {f.remediation}")
            lines.append("")

    return "\n".join(lines)
