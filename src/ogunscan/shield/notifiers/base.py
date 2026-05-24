"""Abstract Notifier interface.

A Notifier is anything that can be told 'a new finding appeared' or 'a
finding resolved'. The daemon doesn't care HOW the notifier delivers
(stdout, email, Slack, webhook, log file) — it just calls the methods.

Notifiers MUST be safe to call from a daemon thread and MUST NOT raise —
if delivery fails, log it and continue. A flapping alert channel cannot
take down the daemon.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...models import Finding
    from ..diff_types import ScanDiff


class Notifier:
    """Abstract base. Subclasses override `notify_new` / `notify_resolved`."""

    name: str = "abstract"

    def notify_new(self, finding: "Finding", scan_path: str) -> None:
        """A finding that was NOT in the previous scan has appeared.
        Subclasses should send their alert here. Default = no-op."""

    def notify_resolved(self, finding: "Finding", scan_path: str) -> None:
        """A finding that WAS in the previous scan is gone in the current scan.
        Subclasses may send a 'fixed' notification. Default = no-op."""

    def notify_scan_summary(self, scan_path: str, total_new: int, total_resolved: int, total_unchanged: int) -> None:
        """Optional per-scan rollup. Default = no-op. Useful for daily-digest
        notifiers that prefer one message per scan rather than one per finding."""
