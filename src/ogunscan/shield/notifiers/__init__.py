"""Shield notifier abstraction + registry.

Phase 2 ships the abstract `Notifier` plus a `StdoutNotifier` impl. Phase 3
adds `EmailNotifier` (Gmail SMTP) and `SlackNotifier` (incoming webhook +
Block Kit). Customers register notifiers in their `~/.ogunscan/shield/config.json`
(Phase 3) — for Phase 2 the daemon uses StdoutNotifier by default.
"""

from typing import Dict, Iterable, List, Type

from .base import Notifier
from .email import EmailNotifier
from .slack import SlackNotifier
from .stdout import StdoutNotifier

__all__ = [
    "Notifier",
    "StdoutNotifier",
    "EmailNotifier",
    "SlackNotifier",
    "REGISTRY",
    "register",
    "get",
    "list_available",
    "auto_wire_from_env",
]


REGISTRY: Dict[str, Type[Notifier]] = {
    "stdout": StdoutNotifier,
    "email": EmailNotifier,
    "slack": SlackNotifier,
}


def register(name: str, cls: Type[Notifier]) -> None:
    """Add a notifier impl to the registry."""
    REGISTRY[name] = cls


def get(name: str) -> Type[Notifier]:
    """Look up a notifier class by registered name. Raises KeyError if unknown."""
    return REGISTRY[name]


def list_available() -> Iterable[str]:
    return list(REGISTRY.keys())


def auto_wire_from_env() -> List[Notifier]:
    """Inspect environment and return the list of notifiers to enable.

    StdoutNotifier is always included (cheap, useful for journalctl /
    launchd logs / `ogunscan shield logs`). Email + Slack opt in only if
    their env vars are configured. This is the daemon's default
    notifier list when no explicit override is passed.
    """
    out: List[Notifier] = [StdoutNotifier()]
    email = EmailNotifier.from_env()
    if email is not None:
        out.append(email)
    slack = SlackNotifier.from_env()
    if slack is not None:
        out.append(slack)
    return out
