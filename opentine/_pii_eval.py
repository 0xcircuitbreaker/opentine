"""Recall and precision of the ``opentine-redaction/3`` PII detectors on a labelled corpus.

The corpus is JSON Lines: ``{"text": ..., "pii": [[kind, exact substring], ...]}``.
A detected span is a true positive when its kind and exact text match a label
not yet matched on that line; everything else detected is a false positive and
every label left over is a false negative. Kinds are compared after folding
``gov-id:*`` into ``gov-id`` and ``classifier:*`` into ``classifier`` for the
summary rows; the per-kind table keeps them apart.

``scripts/pii_eval.py`` prints :func:`table`; docs/PII.md publishes it and a
test holds the two to each other, so the numbers cannot drift from the code.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from opentine._pii import find


def evaluate(lines: list[dict[str, Any]], classifier: Any = None) -> dict[str, Counter[str]]:
    """``{"tp", "fp", "fn"}`` counters by kind."""
    out: dict[str, Counter[str]] = {"tp": Counter(), "fp": Counter(), "fn": Counter()}
    for line in lines:
        text = line["text"]
        wanted = Counter((kind, value) for kind, value in line["pii"])
        for hit in find(text, classifier):
            key = (hit.kind, text[hit.start : hit.end])
            if wanted[key] > 0:
                wanted[key] -= 1
                out["tp"][hit.kind] += 1
            else:
                out["fp"][hit.kind] += 1
        for (kind, _), left in wanted.items():
            out["fn"][kind] += left
    return out


def load(path: Path) -> list[dict[str, Any]]:
    text = path.read_text("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _ratio(numerator: int, denominator: int) -> str:
    return f"{numerator / denominator:.3f}" if denominator else "n/a"


def table(lines: list[dict[str, Any]], classifier: Any = None) -> str:
    """The Markdown table docs/PII.md publishes."""
    counts = evaluate(lines, classifier)
    kinds = sorted(set(counts["tp"]) | set(counts["fp"]) | set(counts["fn"]))
    rows = ["| Detector | TP | FP | FN | Precision | Recall |", "|---|---:|---:|---:|---:|---:|"]
    for kind in [*kinds, "all"]:
        if kind == "all":
            tp, fp, fn = (sum(counts[name].values()) for name in ("tp", "fp", "fn"))
            label = "**all**"
        else:
            tp, fp, fn = counts["tp"][kind], counts["fp"][kind], counts["fn"][kind]
            label = f"`{kind}`"
        rows.append(f"| {label} | {tp} | {fp} | {fn} | {_ratio(tp, tp + fp)} | "
                    f"{_ratio(tp, tp + fn)} |")  # fmt: skip
    return "\n".join(rows)


__all__ = ["evaluate", "load", "table"]
