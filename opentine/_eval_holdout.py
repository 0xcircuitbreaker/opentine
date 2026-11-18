"""``tine eval run --holdout DIR``: refuse runs that touched the holdout (0.60).

The runs scored are those the outputs file and the items name, plus ``--run``.
Each is read from ``--repo`` (a run not stored there is judged by its access
records only) and handed to :func:`opentine._holdout_access.touched`. Any
finding refuses the whole eval with ``eval.holdout-touched``: nothing is signed.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any


class HoldoutTouched(Exception):
    def __init__(self, refusals: list[dict[str, str]]) -> None:
        super().__init__("; ".join(r["detail"] for r in refusals))
        self.refusals = refusals


def _store(repo: str) -> Any:
    try:
        from opentine.repo import Repo

        return Repo.open(Path(repo))
    except Exception:  # noqa: BLE001 - no repository: access records only
        return None


def refuse_touched(args: argparse.Namespace, items: list[dict[str, Any]],
                   outputs: dict[str, dict[str, Any]] | None) -> None:  # fmt: skip
    from opentine._holdout_access import run_text, touched

    names = {row["run"] for row in (outputs or {}).values() if isinstance(row.get("run"), str)}
    names |= {item["run"] for item in items if isinstance(item.get("run"), str)}
    names |= {args.default_run} if args.default_run else set()
    store = _store(args.repo)
    texts: dict[str, str] = {}
    for name in sorted(names):
        try:
            texts[name] = run_text(store.load_run(name)) if store is not None else ""
        except Exception:  # noqa: BLE001 - not stored here
            texts[name] = ""
    found = touched(Path(args.holdout), items, texts, Path(args.repo))
    if found:
        raise HoldoutTouched(found)


__all__ = ["HoldoutTouched", "refuse_touched"]
