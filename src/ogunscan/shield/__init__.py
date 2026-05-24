"""OgunScan Shield — continuous monitoring tier.

Shield runs as a local daemon (launchd on macOS / systemd on Linux). It
watches a registered set of MCP config files for changes, runs the
OgunScan rule engine on each change (and on a configurable schedule),
and emits alerts via pluggable notifiers when new findings appear or
existing ones resolve.

Phase 2 ships: data layer, notifier abstraction (+ stdout impl), file
watcher, daemon loop, CLI commands `add / remove / status / scan-now /
logs / stop`. Phase 3 adds email + Slack notifiers. Phase 4 adds the
license gate (`activate` / `deactivate`).

State + history live at `~/.ogunscan/shield/`.
"""

SHIELD_VERSION = "0.2.0-dev"
