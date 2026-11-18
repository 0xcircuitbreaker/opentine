"""Matching holdout items against runs (0.60): split out of :mod:`opentine._holdout_access`.

``norm`` folds NFKC, case and Cyrillic/Greek lookalikes and keeps letters and
digits; ``shingles`` are word 5-grams of the folded text; :func:`touched`
refuses a scored run that a non-eval access record names, that holds an item in
clear, or that contains an item's shingles at or above :data:`CONTAINMENT`.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

CONTAINMENT = 0.8
SHINGLE = 5
MIN_EXACT = 16
_WORD = re.compile(r"\w+")
# Common Cyrillic/Greek letters that render like Latin ones (casefolded forms).
_LOOKALIKE = str.maketrans("аеорсухіјѕԁɡοαν", "aeopcyxijsdgoav")


def norm(text: str) -> str:
    """NFKC, casefolded, lookalikes folded, only letters and digits: what a match compares."""
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_LOOKALIKE)
    return "".join(ch for ch in folded if ch.isalnum())


def shingles(text: str) -> set[tuple[str, ...]]:
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_LOOKALIKE)
    words = _WORD.findall(folded)
    return {tuple(words[i : i + SHINGLE]) for i in range(len(words) - SHINGLE + 1)}


def item_texts(item: dict[str, Any]) -> list[str]:
    values = [item.get("input"), item.get("expected")]
    return [v if isinstance(v, str) else json.dumps(v, sort_keys=True)
            for v in values if v is not None]  # fmt: skip


def run_text(run: Any) -> str:
    parts = [run.user_prompt or ""] if hasattr(run, "user_prompt") else []
    for step in run.steps:
        parts.append(json.dumps([step.inputs, step.outputs, step.error, step.tool_info],
                                sort_keys=True, ensure_ascii=False, default=str))  # fmt: skip
    return "\n".join(parts)


def _strings(value: Any) -> list[str]:
    """Leaf strings of nested dicts and lists, depth first, without recursion."""
    out, stack = [], [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, (list, tuple)):
            stack.extend(reversed(item))
    return out


def run_flat(run: Any) -> str:
    """:func:`norm` of a run's string values only, so a marker split across fields joins."""
    parts = [run.user_prompt or ""] if hasattr(run, "user_prompt") else []
    for step in run.steps:
        parts += _strings([step.inputs, step.outputs, step.error, step.tool_info])
    return norm("".join(parts))


def touched(folder: Path, items: list[dict[str, Any]], runs: dict[str, str],
            repo: Path | None) -> list[dict[str, str]]:  # fmt: skip
    """``eval.holdout-touched`` refusals: *runs* maps run id to its closure's text."""
    from opentine._holdout_access import exposure

    state = exposure(folder, repo)
    readers = {row["run"] for row in state["records"] if row["purpose"] != "eval"}
    out = []
    for run, text in sorted(runs.items()):
        if run in readers:
            out.append(
                {
                    "code": "eval.holdout-touched",
                    "run": run,
                    "detail": "a non-eval access record unsealed holdout items for it",
                }
            )
            continue
        grams, flat = shingles(text), norm(text)
        for item in items:
            for value in item_texts(item):
                key = norm(value)
                exact = len(key) >= MIN_EXACT and key in flat
                mine = shingles(value)
                share = len(mine & grams) / len(mine) if mine else 0.0
                if exact or share >= CONTAINMENT:
                    how = "in clear" if exact else f"5-gram containment {share:.2f}"
                    out.append({"code": "eval.holdout-touched", "run": run,
                                "detail": f"item {item.get('id')} {how} (threshold "
                                          f"{CONTAINMENT})"})  # fmt: skip
                    break
            else:
                continue
            break
    return out


__all__ = ["CONTAINMENT", "item_texts", "norm", "run_flat", "run_text", "shingles", "touched"]
