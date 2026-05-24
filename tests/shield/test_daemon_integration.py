"""Integration test for the Shield daemon — the brief's gating requirement:

  register a path → modify the file to introduce a CRITICAL finding
  → confirm alert fires within 10 seconds

Runs the daemon in a background thread with a CapturingNotifier so we
can assert what was alerted without needing email or Slack wiring.
"""

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ogunscan.engine import OgunScanner
from ogunscan.models import Finding
from ogunscan.shield.daemon import ShieldDaemon
from ogunscan.shield.notifiers.base import Notifier


class CapturingNotifier(Notifier):
    """Records every notification it receives. Thread-safe."""
    name = "capturing"

    def __init__(self):
        self.new = []
        self.resolved = []
        self.summaries = []
        self._lock = threading.Lock()
        self.event = threading.Event()  # set when ANY new finding arrives

    def notify_new(self, finding, scan_path):
        with self._lock:
            self.new.append((finding, scan_path))
        self.event.set()

    def notify_resolved(self, finding, scan_path):
        with self._lock:
            self.resolved.append((finding, scan_path))

    def notify_scan_summary(self, scan_path, total_new, total_resolved, total_unchanged):
        with self._lock:
            self.summaries.append((scan_path, total_new, total_resolved, total_unchanged))


def _clean_config(path: Path) -> None:
    path.write_text(json.dumps({"mcpServers": {"safe": {"command": "node"}}}), encoding="utf-8")


def _vulnerable_config(path: Path) -> None:
    """Introduces a CRITICAL OGN-200 (hardcoded OpenAI key in env)."""
    path.write_text(json.dumps({
        "mcpServers": {
            "leaky": {
                "command": "node",
                "env": {"OPENAI_KEY": "sk-abc123abc123abc123abc123abc123abc123"}
            }
        }
    }), encoding="utf-8")


def test_end_to_end_alert_fires_within_10_seconds():
    """The brief's gating test."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config_file = tmp_path / "cursor-mcp.json"
        shield_home = tmp_path / "shield-home"
        os.environ["OGUNSCAN_SHIELD_HOME"] = str(shield_home)

        _clean_config(config_file)

        capt = CapturingNotifier()
        # Use a tiny scan_interval so any scheduled-scan fires quickly (test
        # doesn't rely on it, but if it does for some env reason, we don't
        # block for 6h)
        scanner = OgunScanner()
        daemon = ShieldDaemon(
            notifiers=[capt],
            scan_interval_seconds=86400,  # essentially "never" for test duration
            scanner=scanner,
            write_pid=False,  # skip PID file (test isolation)
        )
        daemon.add_path(str(config_file))

        daemon.start()
        consumer = threading.Thread(target=daemon.run, daemon=True)
        consumer.start()
        try:
            # Give the watcher a moment to attach
            time.sleep(0.5)

            # Inject vulnerability → modify the file
            _vulnerable_config(config_file)

            # Wait up to 10s for the notifier to record a new finding
            fired = capt.event.wait(timeout=10.0)
            assert fired, "No alert fired within 10 seconds of vulnerable change"

            # Assert the right thing fired
            assert len(capt.new) >= 1, "Expected at least one new-finding alert"
            rule_ids = {f.rule_id for f, _ in capt.new}
            assert "OGN-200" in rule_ids, f"Expected OGN-200 in alerts, got {rule_ids}"
            # The path that was scanned must be our config file (canonicalised)
            canon = str(Path(config_file).resolve())
            scanned_paths = {p for _, p in capt.new}
            assert canon in scanned_paths, f"Wrong path scanned: {scanned_paths} (expected {canon})"

        finally:
            daemon.stop()
            consumer.join(timeout=3.0)
            daemon.shutdown()
            os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_force_scan_works_without_file_change():
    """`scan-now` should trigger a scan even when files haven't changed."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config_file = tmp_path / "mcp.json"
        shield_home = tmp_path / "home"
        os.environ["OGUNSCAN_SHIELD_HOME"] = str(shield_home)

        _vulnerable_config(config_file)  # vulnerable from the start

        capt = CapturingNotifier()
        daemon = ShieldDaemon(
            notifiers=[capt],
            scan_interval_seconds=86400,
            write_pid=False,
        )
        daemon.add_path(str(config_file))
        daemon.start()
        consumer = threading.Thread(target=daemon.run, daemon=True)
        consumer.start()
        try:
            time.sleep(0.3)
            daemon.force_scan()
            fired = capt.event.wait(timeout=5.0)
            assert fired, "force_scan didn't trigger an alert"
            assert any(f.rule_id == "OGN-200" for f, _ in capt.new)
        finally:
            daemon.stop()
            consumer.join(timeout=3.0)
            daemon.shutdown()
            os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_resolved_finding_fires_resolved_callback():
    """Remove the vulnerability → resolved alert should fire on next scan."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config_file = tmp_path / "mcp.json"
        shield_home = tmp_path / "home"
        os.environ["OGUNSCAN_SHIELD_HOME"] = str(shield_home)

        _vulnerable_config(config_file)
        capt = CapturingNotifier()
        daemon = ShieldDaemon(notifiers=[capt], scan_interval_seconds=86400, write_pid=False)
        daemon.add_path(str(config_file))
        daemon.start()
        consumer = threading.Thread(target=daemon.run, daemon=True)
        consumer.start()
        try:
            time.sleep(0.3)
            # First scan establishes baseline (everything is new)
            daemon.force_scan()
            capt.event.wait(timeout=5.0)
            assert any(f.rule_id == "OGN-200" for f, _ in capt.new)
            # Reset event + capture lists
            capt.event.clear()
            capt.new.clear()
            capt.resolved.clear()
            # Fix the file
            _clean_config(config_file)
            time.sleep(1.0)  # let watcher fire + debounce
            # Wait for resolved
            deadline = time.time() + 5.0
            while time.time() < deadline and not capt.resolved:
                time.sleep(0.1)
            assert any(f.rule_id == "OGN-200" for f, _ in capt.resolved), \
                f"Expected resolved OGN-200; got {[f.rule_id for f, _ in capt.resolved]}"
        finally:
            daemon.stop()
            consumer.join(timeout=3.0)
            daemon.shutdown()
            os.environ.pop("OGUNSCAN_SHIELD_HOME", None)


def test_unchanged_findings_do_not_re_alert():
    """A finding that was present in both scans is unchanged — no second alert."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config_file = tmp_path / "mcp.json"
        shield_home = tmp_path / "home"
        os.environ["OGUNSCAN_SHIELD_HOME"] = str(shield_home)

        _vulnerable_config(config_file)
        capt = CapturingNotifier()
        daemon = ShieldDaemon(notifiers=[capt], scan_interval_seconds=86400, write_pid=False)
        daemon.add_path(str(config_file))
        daemon.start()
        consumer = threading.Thread(target=daemon.run, daemon=True)
        consumer.start()
        try:
            time.sleep(0.3)
            daemon.force_scan()
            capt.event.wait(timeout=5.0)
            first_alert_count = len(capt.new)
            assert first_alert_count >= 1
            # Force a second scan with the file UNCHANGED
            capt.event.clear()
            daemon.force_scan()
            time.sleep(2.0)  # give it a moment
            # New count should still be the same — no duplicate alert
            assert len(capt.new) == first_alert_count, \
                f"Got duplicate alert on unchanged file: first={first_alert_count}, after={len(capt.new)}"
        finally:
            daemon.stop()
            consumer.join(timeout=3.0)
            daemon.shutdown()
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
            import traceback
            print(f"  💥 {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
