"""Scan-to-scan diff logic.

Shield runs the engine on a schedule (and on file change). Each scan
produces a list of Findings. To know what to ALERT on, Shield needs to
compare the current scan against the previous one and emit:

  - `new`        — findings that were not present in the previous scan
  - `resolved`   — findings that were present before and are now gone
  - `unchanged`  — findings that were present in both scans

Identity is `(rule_id, location)` — same rule on the same place in the
config is "the same finding." This is what `Finding.identity()` returns.
"""

from typing import Iterable, List, NamedTuple

from .models import Finding


class FindingDiff(NamedTuple):
    new: List[Finding]
    resolved: List[Finding]
    unchanged: List[Finding]


def diff_findings(previous: Iterable[Finding], current: Iterable[Finding]) -> FindingDiff:
    """Compute the new / resolved / unchanged buckets between two scans.

    The first scan (when `previous` is empty) reports every current finding
    as `new` — Shield's first-run alert behavior is "everything you have
    right now is news to me." Operators can suppress the first-scan burst
    via Shield's `--quiet-first-run` flag (added in Phase 2).
    """
    prev_index = {f.identity(): f for f in previous}
    curr_index = {f.identity(): f for f in current}

    new = [curr_index[k] for k in curr_index if k not in prev_index]
    resolved = [prev_index[k] for k in prev_index if k not in curr_index]
    unchanged = [curr_index[k] for k in curr_index if k in prev_index]

    return FindingDiff(new=new, resolved=resolved, unchanged=unchanged)
