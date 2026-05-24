"""Shield daemon — the always-on loop.

Architecture: single event queue, one consumer thread (`run()`).

  - `ShieldWatcher` thread puts FILE_CHANGED events into the queue
  - A scheduler thread puts SCHEDULED_SCAN events every `scan_interval`
  - SIGUSR1 (and the in-process `force_scan()`) puts FORCE_SCAN events
  - SIGTERM (or in-process `stop()`) puts SHUTDOWN into the queue

The consumer thread processes each event: scans the affected path(s),
diffs against stored findings, fires notifier callbacks for new/resolved,
persists state, appends history.

This single-threaded consumer model means we don't need locks around
state.json — the file is only ever written by the consumer thread.
"""

import os
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from ..engine import OgunScanner
from ..models import Finding
from ..signatures import load_signatures
from ..diff import diff_findings
from . import history, state
from .notifiers.base import Notifier
from .notifiers.stdout import StdoutNotifier
from .paths import ensure_dirs, pid_file, state_file
from .watcher import ShieldWatcher


DEFAULT_SCAN_INTERVAL_SECONDS = 6 * 60 * 60  # 6h


# Event types on the queue
EV_FILE_CHANGED = "file_changed"
EV_SCHEDULED_SCAN = "scheduled_scan"
EV_FORCE_SCAN = "force_scan"
EV_SHUTDOWN = "shutdown"


class ShieldDaemon:
    """Run the Shield monitoring loop.

    Parameters
    ----------
    notifiers : iterable of Notifier
        At least one. Phase 2 default = [StdoutNotifier()]. Phase 3 wires
        Email + Slack here.
    scan_interval_seconds : int
        Time between scheduled full-scan sweeps. Default 6h.
    scanner : OgunScanner or None
        Allows tests to inject a pre-configured scanner. Default = scanner
        built with `load_signatures()` (which honours cache + remote).
    write_pid : bool
        Whether to write a PID file on start. Default True; tests pass False.
    """

    def __init__(
        self,
        notifiers: Optional[Iterable[Notifier]] = None,
        scan_interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        scanner: Optional[OgunScanner] = None,
        write_pid: bool = True,
    ):
        ensure_dirs()
        self.notifiers: List[Notifier] = list(notifiers) if notifiers else [StdoutNotifier()]
        self.scan_interval = scan_interval_seconds
        self.scanner = scanner or OgunScanner(signatures=load_signatures())
        self.write_pid = write_pid
        self._queue: "queue.Queue[tuple]" = queue.Queue()
        self._stop_evt = threading.Event()
        self._scheduler_thread: Optional[threading.Thread] = None
        self._watcher = ShieldWatcher(on_change=self._on_file_change)
        self._state = state.load_state()
        # Sync watcher with registered paths from state
        self._watcher.add_paths(self._state.get("registered_paths", []))

    # ── lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Begin watcher + scheduler threads. Non-blocking. Call `run()` to
        process the event queue."""
        if self.write_pid:
            self._write_pid()
        self._install_signal_handlers()
        self._watcher.start()
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()
        history.record("daemon_started", pid=os.getpid(), watching=len(self._state.get("registered_paths", [])))

    def run(self) -> None:
        """Blocking consumer loop. Returns on shutdown signal."""
        while not self._stop_evt.is_set():
            try:
                event = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            kind = event[0]
            try:
                if kind == EV_SHUTDOWN:
                    break
                elif kind == EV_FILE_CHANGED:
                    _, path = event
                    self._scan_one(path)
                elif kind in (EV_SCHEDULED_SCAN, EV_FORCE_SCAN):
                    self._scan_all()
                elif kind == "reload_state":
                    self._reload_state()
            except Exception as e:
                history.record("error", where=kind, error=str(e))

    def stop(self) -> None:
        """Signal shutdown. Safe to call from any thread."""
        self._stop_evt.set()
        self._queue.put((EV_SHUTDOWN,))

    def shutdown(self) -> None:
        """Tear down threads + clean up PID file. Call after `run()` returns."""
        self._watcher.stop()
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=2.0)
        if self.write_pid:
            self._clear_pid()
        history.record("daemon_stopped")

    def force_scan(self) -> None:
        """Enqueue an immediate full-scan event. Used by `ogunscan shield scan-now`
        (via SIGUSR1) and by tests."""
        self._queue.put((EV_FORCE_SCAN,))

    # ── path registration (callable while daemon is running) ──────────────

    def add_path(self, abs_path: str) -> bool:
        """Register a path. Returns True if new, False if already registered.
        Persists state + adjusts watcher live. Path is canonicalised
        (resolved) so state + watcher use identical keys regardless of
        symlinks or relative input."""
        canon = str(Path(abs_path).expanduser().resolve())
        added = state.register_path(self._state, canon)
        if added:
            state.save_state(self._state)
            self._watcher.add_paths([canon])
            history.record("path_added", path=canon)
        return added

    def remove_path(self, abs_path: str) -> bool:
        canon = str(Path(abs_path).expanduser().resolve())
        removed = state.unregister_path(self._state, canon)
        if removed:
            state.save_state(self._state)
            self._watcher.remove_paths([canon])
            history.record("path_removed", path=canon)
        return removed

    # ── internals ─────────────────────────────────────────────────────────

    def _on_file_change(self, path: str) -> None:
        """Watcher thread → queue."""
        self._queue.put((EV_FILE_CHANGED, path))

    def _scheduler_loop(self) -> None:
        """Background thread: every `scan_interval` seconds, enqueue a sweep."""
        while not self._stop_evt.wait(timeout=self.scan_interval):
            self._queue.put((EV_SCHEDULED_SCAN,))

    def _scan_one(self, path: str) -> None:
        """Scan a single path and emit diff events. Called from consumer thread."""
        if not Path(path).exists():
            # File deleted while watching — surface as a stable info event,
            # don't crash. Keep registration intact in case file returns.
            history.record("path_missing", path=path)
            return
        previous = state.get_findings(self._state, path)
        result = self.scanner.scan_file(Path(path))
        current = result.findings
        d = diff_findings(previous, current)

        for f in d.new:
            for n in self.notifiers:
                n.notify_new(f, path)
            history.record(
                "new_finding",
                path=path,
                rule_id=f.rule_id,
                severity=f.severity.value,
                location=f.location,
                title=f.title,
            )
        for f in d.resolved:
            for n in self.notifiers:
                n.notify_resolved(f, path)
            history.record(
                "resolved_finding",
                path=path,
                rule_id=f.rule_id,
                location=f.location,
            )

        for n in self.notifiers:
            n.notify_scan_summary(path, len(d.new), len(d.resolved), len(d.unchanged))

        state.set_findings(self._state, path, current)
        now = datetime.now(timezone.utc)
        next_at = now + timedelta(seconds=self.scan_interval)
        state.mark_scan_complete(self._state, now, next_at)
        state.save_state(self._state)
        history.record("scan_completed", path=path, new=len(d.new), resolved=len(d.resolved), unchanged=len(d.unchanged))

    def _scan_all(self) -> None:
        paths = list(self._state.get("registered_paths", []))
        history.record("scan_started", paths=len(paths))
        for p in paths:
            self._scan_one(p)

    # ── signal + PID handling ─────────────────────────────────────────────

    def _install_signal_handlers(self) -> None:
        # In test contexts (non-main thread) signal.signal raises ValueError;
        # tests use the in-process force_scan() / stop() instead.
        try:
            signal.signal(signal.SIGTERM, self._handle_sigterm)
            signal.signal(signal.SIGINT, self._handle_sigterm)
            signal.signal(signal.SIGUSR1, self._handle_sigusr1)
            signal.signal(signal.SIGHUP, self._handle_sighup)
        except (ValueError, AttributeError):
            pass

    def _handle_sigterm(self, signum, frame) -> None:
        self.stop()

    def _handle_sigusr1(self, signum, frame) -> None:
        self.force_scan()

    def _handle_sighup(self, signum, frame) -> None:
        """CLI changed state.json (add/remove path) — reload + reconcile watcher."""
        self._queue.put(("reload_state",))

    def _reload_state(self) -> None:
        """Re-read state from disk + reconcile watcher to the new registered set."""
        new_state = state.load_state()
        new_paths = set(new_state.get("registered_paths", []))
        old_paths = set(self._state.get("registered_paths", []))
        for p in new_paths - old_paths:
            self._watcher.add_paths([p])
            history.record("path_added", path=p, via="reload")
        for p in old_paths - new_paths:
            self._watcher.remove_paths([p])
            history.record("path_removed", path=p, via="reload")
        self._state = new_state

    def _write_pid(self) -> None:
        try:
            pid_file().write_text(str(os.getpid()), encoding="utf-8")
        except OSError:
            pass

    def _clear_pid(self) -> None:
        try:
            pid_file().unlink()
        except (OSError, FileNotFoundError):
            pass


def main() -> None:
    """Entry point for `python -m ogunscan.shield.daemon` and the launchd plist."""
    d = ShieldDaemon()
    d.start()
    try:
        d.run()
    finally:
        d.shutdown()


if __name__ == "__main__":
    main()
