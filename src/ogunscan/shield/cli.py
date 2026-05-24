"""Shield CLI subcommands. Wired into the main `ogunscan` CLI by
`ogunscan/cli.py`. Out-of-process commands that modify state on disk
then signal a running daemon (if any) via SIGHUP / SIGUSR1 / SIGTERM.

Phase 2 ships: add, remove, status, scan-now, logs, stop.
Phase 4 adds: activate, deactivate.
"""

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import history, license as _license, state
from .paths import pid_file


def _read_pid() -> int:
    """Return daemon PID if file exists and process is alive, else 0."""
    p = pid_file()
    if not p.exists():
        return 0
    try:
        pid = int(p.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return 0
    if pid <= 0:
        return 0
    try:
        os.kill(pid, 0)  # signal 0 = existence check, doesn't actually signal
        return pid
    except ProcessLookupError:
        return 0
    except PermissionError:
        # Process exists, just not ours. Treat as running.
        return pid


def _signal_daemon(sig: int) -> bool:
    """Send a signal to the running daemon if any. Returns True if sent."""
    pid = _read_pid()
    if not pid:
        return False
    try:
        os.kill(pid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _abs(path: str) -> str:
    return str(Path(path).expanduser().resolve())


# ── subcommand handlers ──────────────────────────────────────────────────


def cmd_shield_add(args: argparse.Namespace) -> int:
    abs_path = _abs(args.path)
    s = state.load_state()
    added = state.register_path(s, abs_path)
    if not added:
        print(f"Already registered: {abs_path}", file=sys.stderr)
        return 0
    state.save_state(s)
    pid = _read_pid()
    if pid:
        _signal_daemon(signal.SIGHUP)
        history.record("path_added", path=abs_path, via="cli", daemon_pid=pid)
        print(f"Registered: {abs_path}  (live — daemon pid {pid} reloaded)")
    else:
        history.record("path_added", path=abs_path, via="cli", daemon_pid=None)
        print(f"Registered: {abs_path}  (daemon not running — will pick up on next start)")
    return 0


def cmd_shield_remove(args: argparse.Namespace) -> int:
    abs_path = _abs(args.path)
    s = state.load_state()
    removed = state.unregister_path(s, abs_path)
    if not removed:
        print(f"Not registered: {abs_path}", file=sys.stderr)
        return 1
    state.save_state(s)
    pid = _read_pid()
    if pid:
        _signal_daemon(signal.SIGHUP)
        history.record("path_removed", path=abs_path, via="cli", daemon_pid=pid)
        print(f"Unregistered: {abs_path}  (live — daemon pid {pid} reloaded)")
    else:
        history.record("path_removed", path=abs_path, via="cli", daemon_pid=None)
        print(f"Unregistered: {abs_path}")
    return 0


def cmd_shield_status(args: argparse.Namespace) -> int:
    s = state.load_state()
    pid = _read_pid()
    paths = s.get("registered_paths", [])
    print("⚔️  OgunScan Shield — status")
    print(f"   Daemon:       {'running (pid ' + str(pid) + ')' if pid else 'not running'}")
    print(f"   Registered:   {len(paths)} path(s)")
    for p in paths:
        existing = "✓" if Path(p).exists() else "✗ missing"
        findings = s.get("findings_by_path", {}).get(p, [])
        sev_counts = _severity_counts(findings)
        print(f"     {existing}  {p}")
        if findings:
            crit = sev_counts.get("CRITICAL", 0)
            high = sev_counts.get("HIGH", 0)
            med = sev_counts.get("MEDIUM", 0)
            print(f"            findings: CRITICAL:{crit} HIGH:{high} MEDIUM:{med}")
    print(f"   Last scan:    {s.get('last_scan_at') or 'never'}")
    print(f"   Next scan:    {s.get('next_scan_at') or 'on demand'}")
    print(f"   Scan count:   {s.get('scan_count', 0)}")
    return 0


def cmd_shield_scan_now(args: argparse.Namespace) -> int:
    if not _signal_daemon(signal.SIGUSR1):
        print("Daemon not running — start it first with: ogunscan shield start", file=sys.stderr)
        return 1
    print("Scan requested. See `ogunscan shield logs --tail 10` for results.")
    return 0


def cmd_shield_logs(args: argparse.Namespace) -> int:
    events = history.tail(n=args.tail)
    if not events:
        print("No history yet.")
        return 0
    for ev in events:
        ts = ev.get("ts", "")
        kind = ev.get("kind", "?")
        extras = {k: v for k, v in ev.items() if k not in ("ts", "kind")}
        extras_str = " ".join(f"{k}={v}" for k, v in extras.items())
        print(f"  {ts}  {kind:18}  {extras_str}")
    return 0


def cmd_shield_stop(args: argparse.Namespace) -> int:
    pid = _read_pid()
    if not pid:
        print("Daemon not running.")
        return 0
    if not _signal_daemon(signal.SIGTERM):
        print(f"Failed to signal pid {pid}", file=sys.stderr)
        return 1
    # Wait briefly for clean shutdown
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if _read_pid() == 0:
            print(f"Daemon stopped (was pid {pid}).")
            return 0
        time.sleep(0.2)
    print(f"Sent SIGTERM to pid {pid} but process still running after 5s.", file=sys.stderr)
    return 1


def cmd_shield_start(args: argparse.Namespace) -> int:
    """Start the daemon in the foreground. Gated by a valid Shield license.
    Use launchd for unattended supervision (see `install-launchd`)."""
    pid = _read_pid()
    if pid:
        print(f"Daemon already running (pid {pid}).", file=sys.stderr)
        return 1
    status = _license.verify_license()
    if not status.valid:
        print(f"⚠️  {status.message}", file=sys.stderr)
        return 2
    print(f"✓ {status.message}")
    from .daemon import ShieldDaemon
    d = ShieldDaemon()
    d.start()
    try:
        d.run()
    finally:
        d.shutdown()
    return 0


def cmd_shield_activate(args: argparse.Namespace) -> int:
    """Verify a license key with Gumroad and persist it locally."""
    key = args.key.strip()
    if not key:
        print("License key cannot be empty.", file=sys.stderr)
        return 1
    status = _license.verify_license(license_key=key, force_refresh=True)
    if not status.valid:
        print(f"⚠️  {status.message}", file=sys.stderr)
        return 2
    _license.write_license_key(key)
    print(f"✓ License activated. {status.message}")
    if status.purchase:
        email = status.purchase.get("email", "")
        sale_id = status.purchase.get("sale_id", "")
        if email:
            print(f"  Purchase: {email}{' · sale ' + sale_id if sale_id else ''}")
    print()
    print("Next steps:")
    print("  ogunscan shield add ~/.cursor/mcp.json        # watch your MCP config")
    print("  ogunscan shield install-launchd               # run unattended (macOS)")
    print("  ogunscan shield start                         # or run in the foreground")
    return 0


def cmd_shield_deactivate(args: argparse.Namespace) -> int:
    """Stop daemon (if running), then remove license key + cache."""
    pid = _read_pid()
    if pid:
        _signal_daemon(signal.SIGTERM)
        deadline = time.time() + 5.0
        while time.time() < deadline and _read_pid():
            time.sleep(0.2)
    _license.clear_license()
    print("✓ License removed. Shield daemon stopped (if it was running).")
    return 0


def cmd_shield_license(args: argparse.Namespace) -> int:
    """Show current license status (offline cache + force-verify with Gumroad)."""
    status = _license.verify_license(force_refresh=args.refresh)
    label = "VALID" if status.valid else "INVALID"
    print(f"License: {label}  ({status.source})")
    print(f"  {status.message}")
    if status.purchase:
        for k in ("email", "sale_id", "product_name", "created_at", "subscription_id"):
            if k in status.purchase:
                print(f"  {k}: {status.purchase[k]}")
    return 0 if status.valid else 2


def cmd_shield_install_launchd(args: argparse.Namespace) -> int:
    """Generate + install the launchd plist for unattended daemon supervision (macOS)."""
    import platform
    if platform.system() != "Darwin":
        print("install-launchd is macOS-only. On Linux, use systemd; see docs.", file=sys.stderr)
        return 1
    home = Path.home()
    template_path = Path(__file__).parent.parent.parent.parent / "docs" / "shield-launchd.plist.template"
    if not template_path.exists():
        # Installed from PyPI: template lives at docs/ in the sdist but not
        # always in the wheel. Fall back to a literal inline plist.
        template = _INLINE_PLIST
    else:
        template = template_path.read_text(encoding="utf-8")
    rendered = template.replace("{{PYTHON}}", sys.executable).replace("{{HOME}}", str(home))
    target = home / "Library" / "LaunchAgents" / "dev.ogunscan.shield.plist"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered, encoding="utf-8")
    print(f"Installed plist: {target}")
    print()
    print("Load it with:")
    print(f"  launchctl load  {target}")
    print(f"  launchctl start dev.ogunscan.shield")
    print()
    print("Stop / unload with:")
    print(f"  launchctl stop   dev.ogunscan.shield")
    print(f"  launchctl unload {target}")
    return 0


def cmd_shield_uninstall_launchd(args: argparse.Namespace) -> int:
    """Unload + remove the launchd plist."""
    import platform
    if platform.system() != "Darwin":
        print("uninstall-launchd is macOS-only.", file=sys.stderr)
        return 1
    target = Path.home() / "Library" / "LaunchAgents" / "dev.ogunscan.shield.plist"
    if not target.exists():
        print("No launchd plist installed.")
        return 0
    # Try to stop + unload first (best-effort; ignore failures)
    import subprocess
    subprocess.run(["launchctl", "stop", "dev.ogunscan.shield"], capture_output=True)
    subprocess.run(["launchctl", "unload", str(target)], capture_output=True)
    target.unlink()
    print(f"Removed: {target}")
    return 0


# Inline fallback plist (used when the package was installed without sdist-side docs)
_INLINE_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.ogunscan.shield</string>
  <key>ProgramArguments</key>
  <array><string>{{PYTHON}}</string><string>-m</string><string>ogunscan.shield.daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>{{HOME}}/.ogunscan/shield/logs/daemon.out.log</string>
  <key>StandardErrorPath</key><string>{{HOME}}/.ogunscan/shield/logs/daemon.err.log</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"""


# ── wiring ──────────────────────────────────────────────────────────────


def add_shield_subparser(sub) -> None:
    """Attach `shield` as a subcommand of the main ogunscan CLI."""
    p_shield = sub.add_parser("shield", help="Continuous monitoring + alerts (Shield tier)")
    shield_sub = p_shield.add_subparsers(dest="shield_cmd", required=True, metavar="<command>")

    p_add = shield_sub.add_parser("add", help="Register an MCP config path to watch")
    p_add.add_argument("path", help="Path to MCP config file")
    p_add.set_defaults(func=cmd_shield_add)

    p_rm = shield_sub.add_parser("remove", help="Unregister a watched path")
    p_rm.add_argument("path", help="Path to unregister")
    p_rm.set_defaults(func=cmd_shield_remove)

    p_st = shield_sub.add_parser("status", help="Show Shield state")
    p_st.set_defaults(func=cmd_shield_status)

    p_sn = shield_sub.add_parser("scan-now", help="Force an immediate scan of all registered paths")
    p_sn.set_defaults(func=cmd_shield_scan_now)

    p_logs = shield_sub.add_parser("logs", help="Show recent Shield events")
    p_logs.add_argument("--tail", "-n", type=int, default=20, help="Show last N events (default 20)")
    p_logs.set_defaults(func=cmd_shield_logs)

    p_stop = shield_sub.add_parser("stop", help="Stop the running daemon")
    p_stop.set_defaults(func=cmd_shield_stop)

    p_start = shield_sub.add_parser("start", help="Start the daemon in the foreground (use launchd for unattended)")
    p_start.set_defaults(func=cmd_shield_start)

    p_act = shield_sub.add_parser("activate", help="Activate Shield with a Gumroad license key")
    p_act.add_argument("key", help="The license key from your Gumroad purchase email")
    p_act.set_defaults(func=cmd_shield_activate)

    p_deact = shield_sub.add_parser("deactivate", help="Stop daemon + remove license key")
    p_deact.set_defaults(func=cmd_shield_deactivate)

    p_lic = shield_sub.add_parser("license", help="Show license status (use --refresh to force a Gumroad check)")
    p_lic.add_argument("--refresh", action="store_true", help="Bypass the 24h cache and re-verify with Gumroad")
    p_lic.set_defaults(func=cmd_shield_license)

    p_inst = shield_sub.add_parser("install-launchd", help="Install macOS launchd plist for unattended supervision")
    p_inst.set_defaults(func=cmd_shield_install_launchd)

    p_uninst = shield_sub.add_parser("uninstall-launchd", help="Uninstall the macOS launchd plist")
    p_uninst.set_defaults(func=cmd_shield_uninstall_launchd)


def _severity_counts(findings):
    counts = {}
    for f in findings:
        sev = f.get("severity", "INFO") if isinstance(f, dict) else f.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts
