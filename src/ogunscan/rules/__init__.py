"""Bundled rule + pattern data, plus the helpers to load it.

`builtin.json` is the offline fallback shipped with every install. It mirrors
the canonical signatures file served from https://ogunscan.dev/signatures/latest.json
that Shield uses for hot updates. The structure is identical so the same
loader works for both sources.
"""

import json
from pathlib import Path
from typing import Any, Dict

_BUILTIN_PATH = Path(__file__).parent / "builtin.json"


def load_builtin() -> Dict[str, Any]:
    """Return the bundled signatures dict. Always succeeds; the JSON file
    is shipped inside the package and is a hard requirement."""
    return json.loads(_BUILTIN_PATH.read_text(encoding="utf-8"))


def builtin_path() -> Path:
    return _BUILTIN_PATH
