"""The verbs of ``tine judge`` (0.89); the parser is :mod:`opentine._cli_judge`.

Each handler returns ``(body, lines, ok)``: the ``--json`` body, the text lines,
and whether the command succeeded (``False`` exits 1).
"""

from __future__ import annotations

import argparse
from fractions import Fraction
from pathlib import Path
from typing import Any

MAX_FILE = 256 << 20


class Refused(ValueError):
    """A refusal with a command-level code (exit 1)."""


def _read(path: str | Path) -> bytes:
    with open(path, "rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ValueError(f"{path} is larger than {MAX_FILE} bytes")
    return raw


def rows(path: str | Path) -> list[Any]:
    from opentine import _json_shallow

    out = []
    for number, line in enumerate(_read(path).decode("utf-8").splitlines(), 1):
        if line.strip():
            try:
                out.append(_json_shallow.loads(line))
            except (ValueError, RecursionError) as exc:
                raise ValueError(f"{path}:{number}: not JSON: {exc}") from exc
    return out


def doc(path: str | Path) -> Any:
    from opentine import _json_shallow

    return _json_shallow.loads(_read(path))


def items(path: str) -> dict[str, dict[str, Any]]:
    from opentine._eval_dataset import check_item

    out: dict[str, dict[str, Any]] = {}
    for number, row in enumerate(rows(path), 1):
        item = check_item(row, f"{path}:{number}")
        if item["id"] in out:
            raise ValueError(f"{path}: duplicate item id {item['id']!r}")
        out[item["id"]] = item
    return out


def digests(found: dict[str, dict[str, Any]]) -> dict[str, str]:
    from opentine._eval_dataset import item_digest

    return {k: item_digest(v) for k, v in found.items()}


def _fraction(text: str, name: str) -> Fraction:
    try:
        return Fraction(str(text))
    except (ValueError, ZeroDivisionError):
        raise ValueError(f"{name} is a decimal") from None


def _now(args: argparse.Namespace) -> str:
    from opentine._audit_game import now

    return args.at or now()


def _repo(args: argparse.Namespace) -> Any:
    from opentine.repo import Repo

    return Repo.open(args.repo)


def _outcomes(path: str) -> dict[str, dict[str, Any]]:
    from opentine._judge_label import STATUSES

    out = {}
    for row in rows(path):
        if not isinstance(row, dict) or not isinstance(row.get("item"), str):
            raise ValueError(f"{path}: each row has an item id and an outcome")
        outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
        if outcome.get("status") not in STATUSES:
            outcome = {"status": "error", "label": None}
        out[row["item"]] = outcome
    return out


def _agreement(args: argparse.Namespace, repo: Any) -> tuple[dict, str]:
    from opentine import _judge_agreement, _rubric_labels

    rubric = _rubric_labels.rubric_digest(_read(args.rubric))
    known = digests(items(args.items))
    found = _rubric_labels.labels(repo, rubric, known)
    plan = _rubric_labels.assignment(known, _rubric_labels.reviewers(repo)[0], args.per_item)
    counted = {i: {r: v for r, v in by.items() if r in plan.get(i, ())}
               for i, by in found["labels"].items()}  # fmt: skip
    outside = sum(len(by) for by in found["labels"].values()) - sum(map(len, counted.values()))
    report = _judge_agreement.report(
        _outcomes(args.judge_labels), counted,
        floor=_fraction(args.floor, "--floor"),
        min_coverage=_fraction(args.min_coverage, "--min-coverage"), seed=args.seed,
        resamples=args.resamples)  # fmt: skip
    report["ignored_labels"] = len(found["ignored"])
    report["unassigned_labels"] = outside  # a reviewer cannot pick the items they label
    report["conflicts"] = found["conflicts"]
    return report, rubric


def agreement(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    report, rubric = _agreement(args, _repo(args))
    lo, hi = report["ci"]
    lines = [
        f"{report['method']} {report['value']} [{lo}, {hi}] over {report['counted']} item(s), "
        f"floor {report['floor']}: " + ("met" if report["meets_floor"] else "not met")
    ]
    lines += [f"advisory: {r}" for r in report["reasons"]]
    body = {"rubric": rubric, "agreement": report, "advisory": not args.strict}
    return body, lines, report["meets_floor"] or not args.strict


def label(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine import _containment_records, _rubric_labels
    from opentine._key_hygiene import ed25519_private

    repo, found = _repo(args), items(args.items)
    if args.item not in found:
        raise ValueError(f"no item {args.item!r} in {args.items}")
    key = ed25519_private(args.key)
    claim = {"convention": _rubric_labels.CONVENTION,
             "rubric": _rubric_labels.rubric_digest(_read(args.rubric)), "item": args.item,
             "item_digest": digests({args.item: found[args.item]})[args.item],
             "label": args.label, "reviewer": _containment_records.fingerprint(key),
             "at": _now(args)}  # fmt: skip
    try:
        oid = _rubric_labels.record(repo, claim, key)
    except _rubric_labels.LabelError as exc:
        raise Refused(str(exc)) from exc
    return {"record": oid, "claim": claim}, [f"labelled {args.item} {args.label}: {oid}"], True


def queue(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine import _rubric_labels

    rubric = _rubric_labels.rubric_digest(_read(args.rubric))
    body = _rubric_labels.queue(_repo(args), rubric, digests(items(args.items)), args.per_item)
    lines = [f"{k}: {len(v['pending'])} pending of {len(v['assigned'])}"
             for k, v in body["reviewers"].items()] or [f"no reviewer: {body['why']}"]  # fmt: skip
    return {"rubric": rubric, **body}, lines, True


def injection(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine._judge_injection import scan_rows

    found = scan_rows([r for r in rows(args.outputs) if isinstance(r, dict)])
    lines = [f"{f['code']} {f['item']} ({f['kind']}): {f['match']}" for f in found]
    return (
        {"findings": found, "advisory": not args.strict},
        lines or ["no finding"],
        not (found and args.strict),
    )


def independence(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine import _judge_lineage, _judge_provenance

    fam = _judge_lineage.family(Path(args.lineage), args.candidate)
    texts = {_judge_provenance.text_digest(_read(p).decode("utf-8")): _read(p).decode("utf-8")
             for p in args.judge_prompt}  # fmt: skip
    judges = []
    for path in args.judge:
        prov = doc(path)
        pin = _judge_provenance.pin(prov)
        judges.append({"provenance": prov, "pin": pin, "prompt": texts.get(prov["prompt_digest"])})
    monitors = []
    for text in args.monitor:
        digest, _, trust = text.partition("=")
        if trust not in ("", "trusted", "untrusted"):
            raise ValueError("--monitor is DIGEST, DIGEST=trusted or DIGEST=untrusted")
        monitors.append({"digest": digest, "trusted": {"": None, "trusted": True,
                                                       "untrusted": False}[trust]})  # fmt: skip
    ancestry = doc(args.ancestry) if args.ancestry else {}
    if not isinstance(ancestry, dict) or not all(isinstance(v, list) for v in ancestry.values()):
        raise ValueError("--ancestry is a JSON object of digest to a list of parent digests")
    found = _judge_lineage.check(
        fam, judges=judges, monitors=monitors, items=rows(args.items) if args.items else [],
        ancestry=ancestry, family_prompts=[_read(p).decode("utf-8") for p in args.family_prompt],
        threshold=_fraction(args.threshold, "--threshold"))  # fmt: skip
    if not fam["known"]:
        found["findings"].insert(
            0,
            {
                "code": "fail:lineage.candidate-unknown",
                "id": args.candidate,
                "detail": "no signed lineage record names the candidate",
            },
        )
    body = {"candidate": args.candidate, "family": {k: fam[k] for k in ("variants", "runs")},
            **found}  # fmt: skip
    lines = [f"{f['code']} {f['id']}: {f['detail']}" for f in found["findings"]]
    return body, lines or ["independent"], not found["findings"]


def validate(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine import _judge_provenance, _judge_validation
    from opentine._key_hygiene import ed25519_private

    repo = _repo(args)
    if args.judge:
        subject = {"kind": "judge", "id": _judge_provenance.pin(doc(args.judge))}
    else:
        subject = {"kind": "monitor", "id": args.monitor}
    report, rubric = _agreement(args, repo)
    raw = _read(args.adversarial)
    cases = _judge_validation.adversarial(rows(args.adversarial), raw, args.max_fooled)
    try:
        done = _judge_validation.validate(repo, subject, rubric=rubric, cases=cases,
                                          agreement=report, key=ed25519_private(args.key),
                                          at=_now(args))  # fmt: skip
    except _judge_validation.ValidationError as exc:
        raise Refused(str(exc)) from exc
    return done, [f"validated {subject['kind']} {subject['id']}: {done['record']}"], True


def classify(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine._cli_judge_classify import classify as run

    return run(args)


HANDLERS = {"classify": classify, "agreement": agreement, "label": label, "queue": queue,
            "injection": injection, "independence": independence,
            "validate": validate}  # fmt: skip

__all__ = ["HANDLERS", "Refused", "digests", "doc", "items", "rows"]
