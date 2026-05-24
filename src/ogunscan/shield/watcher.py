"""File watcher — uses `watchdog` to emit a 'path changed' callback when
any registered MCP config file changes on disk.

Implementation note: watchdog watches *directories*. We schedule one
observer entry per unique parent directory and filter events down to
our registered set of filenames. Editor saves often produce a flurry
of events in milliseconds (atomic write = create-temp / rename); we
debounce per-path with a small delay so each save fires the callback
exactly once.
"""

import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Set

from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer


DebouncedCallback = Callable[[str], None]


class _PathHandler(FileSystemEventHandler):
    """One handler per parent directory. Calls `callback(path)` on any
    relevant event for any path in `watched`, debouncing per-path."""

    def __init__(self, watched: Set[str], callback: DebouncedCallback, debounce_seconds: float = 0.5):
        self.watched = watched
        self.callback = callback
        self.debounce_seconds = debounce_seconds
        self._last_fire: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _is_watched(self, path_str: str) -> bool:
        return path_str in self.watched

    def _fire(self, path_str: str) -> None:
        now = time.time()
        with self._lock:
            last = self._last_fire.get(path_str, 0.0)
            if now - last < self.debounce_seconds:
                return
            self._last_fire[path_str] = now
        try:
            self.callback(path_str)
        except Exception:
            # Notifier callbacks must not crash the observer thread.
            # Any exception here is a daemon-side bug worth fixing,
            # but the daemon must keep running for other paths.
            pass

    def on_modified(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileModifiedEvent) and self._is_watched(event.src_path):
            self._fire(event.src_path)

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileCreatedEvent) and self._is_watched(event.src_path):
            self._fire(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileMovedEvent):
            # Treat a move-into a watched path as a modification of the destination.
            if hasattr(event, "dest_path") and self._is_watched(event.dest_path):
                self._fire(event.dest_path)


class ShieldWatcher:
    """Manages watchdog observers for a dynamic set of registered paths.

    Adding/removing paths takes effect immediately (no restart needed).
    Thread-safe.
    """

    def __init__(self, on_change: DebouncedCallback, debounce_seconds: float = 0.5):
        self.on_change = on_change
        self.debounce_seconds = debounce_seconds
        self._observer = Observer()
        self._handlers: Dict[str, _PathHandler] = {}   # parent_dir -> handler
        self._registered: Set[str] = set()             # absolute file paths
        self._started = False
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._observer.start()
            self._started = True

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            if not self._started:
                return
            self._observer.stop()
            self._observer.join(timeout=timeout)
            self._started = False

    def add_paths(self, paths: Iterable[str]) -> None:
        """Register one or more absolute file paths. Watches their parent dirs."""
        with self._lock:
            for raw in paths:
                p = str(Path(raw).expanduser().resolve())
                if p in self._registered:
                    continue
                self._registered.add(p)
                parent = str(Path(p).parent)
                if parent not in self._handlers:
                    handler = _PathHandler({p}, self.on_change, self.debounce_seconds)
                    self._handlers[parent] = handler
                    try:
                        self._observer.schedule(handler, parent, recursive=False)
                    except (FileNotFoundError, OSError):
                        # Parent dir doesn't exist yet — daemon will note via
                        # the scheduled scan path and re-attempt next reconcile.
                        del self._handlers[parent]
                        self._registered.discard(p)
                        continue
                else:
                    self._handlers[parent].watched.add(p)

    def remove_paths(self, paths: Iterable[str]) -> None:
        """Unregister one or more absolute file paths."""
        with self._lock:
            for raw in paths:
                p = str(Path(raw).expanduser().resolve())
                if p not in self._registered:
                    continue
                self._registered.discard(p)
                parent = str(Path(p).parent)
                handler = self._handlers.get(parent)
                if handler:
                    handler.watched.discard(p)
                    # If no more files in this parent dir, drop the watcher entry
                    if not handler.watched:
                        try:
                            self._observer.unschedule(self._observer_watches_for(parent))
                        except (KeyError, AttributeError):
                            pass
                        del self._handlers[parent]

    def registered(self) -> List[str]:
        with self._lock:
            return sorted(self._registered)

    # ── internal: workaround for watchdog Observer not exposing unschedule-by-path ──

    def _observer_watches_for(self, parent: str):
        for watch in list(self._observer._watches):
            try:
                if watch.path == parent:
                    return watch
            except AttributeError:
                continue
        raise KeyError(parent)
