"""Shield notifier abstraction + registry.

Phase 2 ships the abstract `Notifier` plus a `StdoutNotifier` impl. Phase 3
adds `EmailNotifier` (Gmail SMTP) and `SlackNotifier` (incoming webhook +
Block Kit). Customers register notifiers in their `~/.ogunscan/shield/config.json`
(Phase 3) — for Phase 2 the daemon uses StdoutNotifier by default.
"""

from typing import Dict, Iterable, Type

from .base import Notifier
from .stdout import StdoutNotifier

__all__ = ["Notifier", "StdoutNotifier", "REGISTRY", "register", "get"]


REGISTRY: Dict[str, Type[Notifier]] = {
    "stdout": StdoutNotifier,
}


def register(name: str, cls: Type[Notifier]) -> None:
    """Add a notifier impl to the registry. Phase 3 calls this for email + slack."""
    REGISTRY[name] = cls


def get(name: str) -> Type[Notifier]:
    """Look up a notifier class by registered name. Raises KeyError if unknown."""
    return REGISTRY[name]


def list_available() -> Iterable[str]:
    return list(REGISTRY.keys())
