"""StdoutNotifier — Phase 2 default. Prints alerts to stdout (or a
configured stream) and to Shield's history file via the daemon.

Used as the bootstrap notifier and by tests (where we override the stream
to capture output)."""

import sys
from typing import TextIO

from ...models import Finding
from .base import Notifier


class StdoutNotifier(Notifier):
    name = "stdout"

    def __init__(self, stream: TextIO = None):
        self.stream = stream if stream is not None else sys.stdout

    def notify_new(self, finding: Finding, scan_path: str) -> None:
        self._write(
            f"🛡  NEW   [{finding.severity.value}] {finding.rule_id} — {finding.title}\n"
            f"          path:  {scan_path}\n"
            f"          where: {finding.location}\n"
            f"          fix:   {finding.remediation}\n"
        )

    def notify_resolved(self, finding: Finding, scan_path: str) -> None:
        self._write(
            f"✓  RESOLVED [{finding.rule_id}] at {finding.location} ({scan_path})\n"
        )

    def notify_scan_summary(self, scan_path: str, total_new: int, total_resolved: int, total_unchanged: int) -> None:
        self._write(
            f"📋 scan {scan_path} — new:{total_new} resolved:{total_resolved} unchanged:{total_unchanged}\n"
        )

    def _write(self, msg: str) -> None:
        try:
            self.stream.write(msg)
            self.stream.flush()
        except (OSError, ValueError):
            pass  # Closed stream during shutdown is fine
