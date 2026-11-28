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


def _opts(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._label_report import settings

    return settings(floor=args.floor, alpha=args.alpha, seed=args.seed,
                    resamples=args.resamples, min_items=args.min_items,
                    min_coverage=args.min_coverage)  # fmt: skip


def _report(args: argparse.Namespace, pin: str | None) -> dict[str, Any]:
    from opentine._label_queue import LabelError
    from opentine._label_report import report

    try:
        return report(Path(args.repo), args.queue, _opts(args), judge_pin=pin)
    except LabelError as exc:
        raise Refused(str(exc)) from exc


def _pin(path: str) -> str:
    from opentine import _judge_provenance

    found = doc(path)
    if _judge_provenance.check(found):
        raise ValueError(f"{path} is not judge provenance")
    return _judge_provenance.pin(found)


def agreement(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    """Human agreement over a queue and each revealed judge's, recomputed (advisory)."""
    row = _report(args, _pin(args.judge) if args.judge else None)
    human = row["human"]
    top = human[human["primary"]]
    lines = [f"human: {human['items']} item(s), {human['reviewers']} reviewer(s), "
             f"{human['primary']} {top['value']} [{top['lower']}, {top['upper']}]"]  # fmt: skip
    for j in row["judges"]:
        k, m = j["judge_vs_consensus"], j["multi_rater"]
        lines.append(f"judge {j['judge'][:24]}: kappa {k['value']} [{k['lower']}, {k['upper']}] "
                     f"alpha {m['value']} [{m['lower']}, {m['upper']}] coverage {j['coverage']} "
                     f"{'ok' if j['floor_ok'] else 'below floor'}")  # fmt: skip
    ok = human["floor_ok"] and bool(row["judges"]) and all(j["floor_ok"] for j in row["judges"])
    lines += [] if row["judges"] else ["advisory: no judge was revealed in this queue"]
    return {**row, "ok": ok, "advisory": not args.strict}, lines, ok or not args.strict


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
    from opentine import _judge_validation
    from opentine._key_hygiene import ed25519_private

    repo, pin = _repo(args), _pin(args.judge)
    found = _report(args, pin)
    if not found["judges"]:
        raise Refused(f"judge.validation-failed: queue {args.queue} revealed no outcome of {pin}")
    row = found["judges"][0]
    raw = _read(args.adversarial_outcomes)
    cases = _judge_validation.adversarial(rows(args.adversarial), raw, pin, repo.path,
                                          args.max_fooled)  # fmt: skip
    queue = {"name": args.queue, "queue_sha256": found["queue_sha256"],
             "reveal_seq": row["reveal_seq"]}  # fmt: skip
    try:
        done = _judge_validation.validate(repo, {"kind": "judge", "id": pin},
                                          rubric=found["rubric_sha256"], queue=queue, cases=cases,
                                          agreement=row, key=ed25519_private(args.key),
                                          at=_now(args))  # fmt: skip
    except _judge_validation.ValidationError as exc:
        raise Refused(str(exc)) from exc
    return done, [f"validated judge {pin}: {done['record']}"], True


def classify(args: argparse.Namespace) -> tuple[dict, list[str], bool]:
    from opentine._cli_judge_classify import classify as run

    return run(args)


HANDLERS = {"classify": classify, "agreement": agreement, "injection": injection,
            "independence": independence,
            "validate": validate}  # fmt: skip

__all__ = ["HANDLERS", "Refused", "doc", "items", "rows"]
