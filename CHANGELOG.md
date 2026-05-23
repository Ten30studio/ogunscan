# Changelog

All notable changes to OgunScan are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

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
