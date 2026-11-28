"""Agreement reports over a verified label queue (0.89).

``human(state)`` measures reviewer-vs-reviewer agreement: Krippendorff's alpha
over every item with two or more labels, Fleiss' kappa when every such item has
the same number of labels, and Cohen's kappa when exactly two reviewers labelled.

``judge(state, outputs, reveal)`` measures a judge against the reviewers: each
item's *consensus* is its unique most frequent human label (ties are left out
and counted), and Cohen's kappa compares the judge's label with it. Only labels
recorded before the judge's reveal count. A judge output line is a label
(``{"item_sha256", "label"}``) or an explicit abstention (``{"item_sha256",
"abstain": true}``); anything else -- unparsable, a label outside the rubric, a
line naming an item twice -- is an *error*. Neither an abstention nor an error is
ever scored as a label or as 0; both lower ``coverage``.

The floor holds when the kappa's lower bound is defined and at least ``floor``,
coverage is at least ``min_coverage`` and at least ``min_items`` items were
compared. Numbers are six-place decimal strings; undefined values are ``null``.
"""

from __future__ import annotations

import re
from collections import Counter
from fractions import Fraction
from typing import Any

from opentine._label_stats import bootstrap, cohen, fleiss, krippendorff, passes

_ERROR = object()
DECIMAL = re.compile(r"(0|1)(\.[0-9]{1,6})?")
DEFAULTS = {"floor": "0.6", "alpha": "0.05", "seed": 0, "resamples": 2000, "min_items": 20,
            "min_coverage": "0.8"}  # fmt: skip


def _text(value: Any) -> Any:
    from opentine._eval_stats import text

    return text(value) if isinstance(value, Fraction) else value


def _row(found: dict[str, Any]) -> dict[str, Any]:
    return {k: _text(v) for k, v in found.items()}


def settings(**given: Any) -> dict[str, Any]:
    out = {**DEFAULTS, **{k: v for k, v in given.items() if v is not None}}
    for name in ("floor", "alpha", "min_coverage"):
        if not DECIMAL.fullmatch(str(out[name])):
            raise ValueError(f"{name} must be a decimal in [0, 1] (up to six places)")
        value = Fraction(str(out[name]))
        if not 0 <= value <= 1 or (name == "alpha" and value == 0):
            raise ValueError(f"{name} must be a decimal in [0, 1]")
        out[name] = str(out[name])
    for name in ("seed", "resamples", "min_items"):
        if isinstance(out[name], bool) or not isinstance(out[name], int) or out[name] < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    return out


def _units(state: dict[str, Any], before: int | None) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for (who, item), row in state["labels"].items():
        if before is None or row["seq"] < before:
            out.setdefault(item, {})[who] = row["label"]
    return out


def human(state: dict[str, Any], opts: dict[str, Any], before: int | None = None) -> dict:
    units = _units(state, before)
    multi = [sorted(v.values()) for v in units.values() if len(v) >= 2]
    reviewers = sorted({who for v in units.values() for who in v})
    kw = {"seed": opts["seed"], "resamples": opts["resamples"], "alpha": Fraction(opts["alpha"])}
    found = {"krippendorff": bootstrap(multi, krippendorff, metric="krippendorff", **kw),
             "fleiss": bootstrap(multi, fleiss, metric="fleiss", **kw)}  # fmt: skip
    if len(reviewers) == 2:
        a, b = reviewers
        pairs = [(v[a], v[b]) for v in units.values() if a in v and b in v]
        found["cohen"] = bootstrap(pairs, cohen, metric="cohen", **kw)
    else:
        found["cohen"] = {"value": None, "reason": "Cohen's kappa needs exactly two reviewers",
                          "lower": None, "upper": None, "undefined_resamples": None}  # fmt: skip
    primary = "cohen" if len(reviewers) == 2 else "krippendorff"
    return {"items": len(units), "pairable": len(multi), "reviewers": len(reviewers),
            **{k: _row(v) for k, v in found.items()}, "primary": primary,
            "floor_ok": passes(found[primary], Fraction(opts["floor"]))}  # fmt: skip


def parse_outputs(raw: bytes, labels: list[str]) -> tuple[dict[str, str | None], int]:
    """``({item: label, or None for an abstention}, errors)`` of a judge's output lines."""
    from opentine import _json_shallow

    answers: dict[str, list] = {}
    errors = 0
    for line in raw.split(b"\n"):
        if not line.strip():
            continue
        try:
            row = _json_shallow.loads(line)
        except (ValueError, UnicodeDecodeError):
            row = None
        item = row.get("item_sha256") if isinstance(row, dict) else None
        if not isinstance(item, str):
            errors += 1
        elif set(row) == {"item_sha256", "abstain"} and row["abstain"] is True:
            answers.setdefault(item, []).append(None)
        elif set(row) == {"item_sha256", "label"} and row["label"] in labels:
            answers.setdefault(item, []).append(row["label"])
        else:
            answers.setdefault(item, []).append(_ERROR)
    found = {}
    for item, given in answers.items():  # an item named twice is never one of its answers
        if len(given) == 1 and given[0] is not _ERROR:
            found[item] = given[0]
        else:
            errors += len(given)
    return found, errors


def judge(state: dict[str, Any], raw: bytes, reveal: dict[str, Any],
          opts: dict[str, Any]) -> dict[str, Any]:  # fmt: skip
    units = _units(state, reveal["seq"])
    outputs, errors = parse_outputs(raw, state["rubric"]["labels"])
    consensus, ties = {}, 0
    for item, votes in units.items():
        ranked = Counter(votes.values()).most_common()
        if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
            ties += 1
        else:
            consensus[item] = ranked[0][0]
    abstained = sum(1 for item in consensus if item in outputs and outputs[item] is None)
    pairs = [(outputs[i], c) for i, c in sorted(consensus.items()) if outputs.get(i) is not None]
    kw = {"seed": opts["seed"], "resamples": opts["resamples"], "alpha": Fraction(opts["alpha"])}
    kappa = bootstrap(pairs, cohen, metric="cohen", **kw)
    coverage = Fraction(len(pairs), len(consensus)) if consensus else None
    reasons = []
    if not passes(kappa, Fraction(opts["floor"])):
        reasons.append("the kappa lower bound is undefined or below the floor")
    if coverage is None or coverage < Fraction(opts["min_coverage"]):
        reasons.append("the judge labelled too few consensus items (abstained or erred)")
    if len(pairs) < opts["min_items"]:
        reasons.append(f"fewer than {opts['min_items']} items were compared")
    return {"judge": reveal["judge"], "outputs_sha256": reveal["outputs_sha256"],
            "reveal_seq": reveal["seq"], "consensus_items": len(consensus), "ties": ties,
            "compared": len(pairs), "abstained": abstained, "errors": errors,
            "missing": sum(1 for i in consensus if i not in outputs),
            "coverage": _text(coverage), "cohen": _row(kappa), "floor": opts["floor"],
            "floor_ok": not reasons, "reasons": reasons}  # fmt: skip


def report(repo: Any, name: str, opts: dict[str, Any], judge_pin: str | None = None) -> dict:
    """The full report of queue *name*: human agreement and each revealed judge's."""
    import hashlib

    from opentine._label_queue import LabelError, folder, read

    state = read(repo, name)
    judges, seen = [], set()
    for row in state["reveals"]:
        if row["judge"] in seen or (judge_pin and row["judge"] != judge_pin):
            continue  # only a judge's first reveal counts
        seen.add(row["judge"])
        path = folder(repo, name) / "judge" / f"{row['outputs_sha256']}.jsonl"
        raw = path.read_bytes() if path.is_file() else b""
        if hashlib.sha256(raw).hexdigest() != row["outputs_sha256"]:
            raise LabelError("labels.chain", f"revealed judge outputs {path.name} are missing "
                             "or altered")  # fmt: skip
        judges.append(judge(state, raw, row, opts))
    return {"queue": name, "queue_sha256": state["queue"], "rubric_sha256": state["rubric_sha256"],
            "entries": state["seq"],
            "settings": opts, "human": human(state, opts), "judges": judges}  # fmt: skip


__all__ = ["DECIMAL", "DEFAULTS", "human", "judge", "parse_outputs", "report", "settings"]
