"""``tine judge classify`` (0.89): label judges and ensembles over items.

Every ``--judge`` is a label judge (:mod:`opentine._judge_label`). Before any
model is called, the members' independence is checked
(:func:`opentine._judge_ensemble.independence`): fewer independent groups than
``--min-independent`` (default 2 for an ensemble, 1 for one judge) refuses with
``fail:judge.ensemble-not-independent`` and calls nothing. Each item's outcome is
the aggregate of the group votes; abstains and errors are kept, never scored 0.
Candidate outputs are scanned for text aimed at the judge
(:mod:`opentine._judge_injection`); those findings are advisory.
"""

from __future__ import annotations

import argparse
import json
from fractions import Fraction
from pathlib import Path
from typing import Any


def _outputs(args: argparse.Namespace, found: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from opentine._cli_judge_ops import rows

    if not args.outputs:
        missing = [k for k, v in found.items() if "output" not in v]
        if missing:
            raise ValueError(f"item {missing[0]!r} has no output and no --outputs was given")
        return {k: v["output"] for k, v in found.items()}
    out: dict[str, Any] = {}
    for row in rows(args.outputs):
        name = row.get("item", row.get("id")) if isinstance(row, dict) else None
        if not isinstance(name, str) or "output" not in row:
            raise ValueError(f"{args.outputs}: each row has an item id and an output")
        if name in out:
            raise ValueError(f"{args.outputs}: two outputs for item {name!r}")
        out[name] = row["output"]
    return out


def _members(args: argparse.Namespace, labels: list[str]) -> list[Any]:
    from opentine._cli_judge_ops import _read
    from opentine._judge_label import label_judge

    if len(args.prompt or []) not in (0, 1, len(args.judge)):
        raise ValueError("give one --prompt, or one per --judge")
    if args.lineage_of and len(args.lineage_of) != len(args.judge):
        raise ValueError("give one --lineage-of per --judge")
    rubric = _read(args.rubric).decode("utf-8") if args.rubric else None
    prompts = [_read(p).decode("utf-8") for p in args.prompt or []]
    runs = Path(args.runs_dir) if args.runs_dir else None
    out = []
    for n, spec in enumerate(args.judge):
        prompt = prompts[n] if len(prompts) > 1 else (prompts[0] if prompts else None)
        out.append(label_judge(spec, labels, prompt=prompt, rubric=rubric, runs_dir=runs))
    return out


def classify(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine._cli_judge_ops import _fraction, items
    from opentine._judge_ensemble import aggregate, independence
    from opentine._judge_injection import scan
    from opentine._judge_label import check_labels

    labels = check_labels([x.strip() for x in args.labels.split(",") if x.strip()])
    if args.positive is not None and args.positive not in labels:
        raise ValueError(f"--positive {args.positive!r} is not one of the labels")
    if args.aggregate != "majority" and len(labels) != 2:
        raise ValueError(f"--aggregate {args.aggregate} needs exactly two labels")
    found = items(args.items)
    outputs = _outputs(args, found)
    judges = _members(args, labels)
    desc = [{"provenance": j.provenance, "prompt": j.prompt,
             "lineage": args.lineage_of[n] if args.lineage_of else None}
            for n, j in enumerate(judges)]  # fmt: skip
    need = args.min_independent if args.min_independent is not None else min(2, len(judges))
    ind = independence(desc, min_independent=need)
    members = [{"pin": j.version, "model": j.provenance["model"],
                "prompt_digest": j.provenance["prompt_digest"],
                "lineage": d["lineage"]} for j, d in zip(judges, desc, strict=True)]  # fmt: skip
    head = {"labels": labels, "aggregate": args.aggregate, "members": members,
            "independence": ind}  # fmt: skip
    if ind["findings"]:
        lines = [f"{f['code']}: {f['detail']}" for f in ind["findings"]]
        return {**head, "rows": [], "advisories": [], "counts": {}}, lines, False
    cap = _fraction(args.max_abstain, "--max-abstain")
    if not 0 <= cap <= 1:
        raise ValueError("--max-abstain is in [0, 1]")
    out_rows, advisories = [], []
    counts = {"label": 0, "abstain": 0, "error": 0}
    for name in sorted(found):
        if name not in outputs:
            out_rows.append(
                {
                    "item": name,
                    "outcome": {
                        "status": "error",
                        "label": None,
                        "probability": None,
                        "reason": "no output",
                    },
                    "members": [],
                }
            )
            counts["error"] += 1
            continue
        advisories += scan(outputs[name], item=name)
        each = [j(found[name], outputs[name]) for j in judges]
        result = aggregate(each, ind["groups"], method=args.aggregate, positive=args.positive,
                           labels=labels, max_abstain=Fraction(cap))  # fmt: skip
        if all(o["status"] == "error" for o in each):
            result = {**result, "status": "error"}
        counts[result["status"]] += 1
        out_rows.append({"item": name, "outcome": result, "members": each})
    if args.out:
        text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in out_rows)
        Path(args.out).write_bytes(text.encode("utf-8"))
    lines = [f"{r['item']}: {r['outcome']['status']} {r['outcome'].get('label') or ''}".rstrip()
             for r in out_rows]  # fmt: skip
    lines += [f"{a['code']} {a['item']} ({a['kind']})" for a in advisories]
    return {**head, "rows": out_rows, "advisories": advisories, "counts": counts}, lines, True


__all__ = ["classify"]
