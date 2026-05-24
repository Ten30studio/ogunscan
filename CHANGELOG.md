# Changelog

All notable changes to OgunScan are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added (Shield internal — not on PyPI yet)
- **`ogunscan.shield` package** (file watcher + scheduled scan + state + history + CLI). Phase 2 of the OgunScan Shield $9/mo continuous-monitoring tier build.
- New CLI subcommands: `ogunscan shield {add,remove,status,scan-now,logs,stop,start,install-launchd,uninstall-launchd}`. Hidden from free-tier users by the license gate (Phase 4); functional today via `python -m ogunscan.shield.daemon`.
- `watchdog>=3.0` declared as optional `[shield]` extra in pyproject. Free CLI install (`pip install ogunscan`) remains zero-dep.
- macOS `launchd` plist template + `install-launchd` / `uninstall-launchd` CLI commands for unattended daemon supervision.
- 28 new tests under `tests/shield/`: state persistence (atomic write, schema, idempotent register, roundtrip), history (append, tail, malformed-line skip, write-failure non-fatal), notifiers (abstract contract, stdout impl, registry), daemon integration (end-to-end alert fires within 10s on file change, force_scan, resolved_finding callback, unchanged-no-double-alert).

### Operational
- Shield daemon state at `~/.ogunscan/shield/` (state.json + history/*.jsonl + daemon.pid + logs/).
- `OGUNSCAN_SHIELD_HOME` env override for testing + advanced users.
- Daemon signals: SIGTERM → graceful stop, SIGUSR1 → force scan, SIGHUP → reload registered paths from state.json.

## [0.1.3] — 2026-05-24

### Added
- **Hot-updated rule signatures.** Detection rules now load from
  `src/ogunscan/rules/builtin.json` (bundled) with optional refresh from
  `https://ogunscan.dev/signatures/latest.json` (24h cache). Adding a new
  credential or injection pattern no longer requires a release — push the
  updated JSON, every install picks it up on the next scan.
- **`ogunscan.signatures.load_signatures()`** — pure-stdlib loader with
  the cache + network + builtin fallback chain. Foundation for the
  upcoming Shield daemon.
- **`ogunscan.diff.diff_findings()`** — compare two scans, get
  `(new, resolved, unchanged)` buckets. Foundation for Shield's "alert on
  new finding only" behavior.
- `python -m ogunscan` entry point (via `src/ogunscan/__main__.py`).
- 18 new tests: 9 for diff logic, 9 for signature loader (with mocked
  network for offline determinism).

### Changed
- **Package layout: single module → package.** `src/ogunscan.py` →
  `src/ogunscan/{__init__, models, engine, reporter, cli, diff, signatures, rules/}`.
  CLI entry point unchanged (`ogunscan = "ogunscan:cli"`); public API
  unchanged (`from ogunscan import OgunScanner, Severity, Finding, ScanResult, format_report`).
- `pyproject.toml`: `py-modules` replaced with `[tool.setuptools.packages.find]`
  + `[tool.setuptools.package-data]` to ship `rules/builtin.json`.

### Operational
- New endpoint live: `https://ogunscan.dev/signatures/latest.json` —
  seeded with the same 8 rules + pattern data shipped in the package.

## [0.1.2] — 2026-05-23

### Changed
- **Module rename: `scanner` → `ogunscan`.** Users now import the canonical
  package name:

  ```python
  from ogunscan import OgunScanner, Severity
  ```

  The previous `import scanner` form was an oversight in v0.1.1 and is gone.
  CLI behavior is unchanged (`ogunscan scan …` works identically).

### Added
- This `CHANGELOG.md`.

### Operational
- First release published via GitHub Actions trusted publishing — no static
  PyPI token used. Future releases ship via `git tag vX.Y.Z`.

## [0.1.1] — 2026-05-23

### Added
- `LICENSE` (MIT).
- `pyproject.toml` (PEP 621); supersedes legacy `setup.py`.
- `.gitignore`.
- GitHub Actions test workflow — Ubuntu + macOS × Python 3.8 / 3.10 / 3.12 / 3.13.
- CLI subparsers: `scan`, `rules`, `version`.
- `ogunscan rules` — prints all detection rules with severity + description.
- `--ignore RULE` (repeatable) — suppress individual rule IDs.
- Smart verb fallback — `ogunscan path.json` works without explicit `scan` verb.

### Fixed
- `--json` output: nested `Severity` enums now serialize correctly (pre-existing
  bug in v0.1.0).

### Changed
- Project URLs use canonical capital-T `Ten30studio` GitHub case.
- README rewritten with example output, rule reference table, and CI snippet.

### Removed
- Legacy `setup.py` (replaced by `pyproject.toml`).
- Accidentally-committed `src/__pycache__/scanner.cpython-314.pyc`.

## [0.1.0] — 2026-05-23

### Added
- Initial public scaffold.
- Core scanner engine — 8 detection rules covering URLs, credentials, prompt
  injection, dangerous permissions, and supply-chain risk.
- Six rule families: OGN-100 (suspicious URL), OGN-101 (unencrypted), OGN-200
  /-201/-202 (credentials), OGN-300 (prompt injection), OGN-400 (dangerous
  permissions), OGN-500 (unverified package).
- CLI with auto-detect for Claude Desktop + Cursor configs.
- JSON output mode.
- Landing page (`site/index.html`).
- Test suite (6 tests, all passing).
