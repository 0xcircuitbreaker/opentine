"""Trusted re-scoring (0.85): ``tine eval rescore EVAL_DIR``.

The eval folder must verify and carry ``scorer.json`` (an ``--isolate`` run).
The recorded scorer is run again under isolation, in a fresh empty workspace,
on the outputs the caller names (``--outputs``, or the dataset's own), and each
item's re-score is compared with the signed verdict's score. The closure the
re-run loaded is compared with the recorded one too. The result is a signed
``opentine.rescore-report/1`` (a file convention under its own signing domain,
like the reproduce report): ``verdict`` is ``agree`` only when the closure is the
same and every item's score is.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine import _experiment as exp
from opentine import _scorer_closure as closure

CONVENTION = "opentine.rescore-report/1"
DOMAIN = b"opentine.rescore-report.v1:"
FIELDS = ("convention", "eval", "dataset", "scorer_version", "closure", "rescored_closure",
          "closure_agree", "rows", "agreed", "disagreed", "verdict", "isolation",
          "created_at", "signer")  # fmt: skip


def rescore(folder: Path, items: list[dict[str, Any]], outputs: dict[str, dict] | None, *,
            key: Any, inputs: list[Path] | None = None, lockfile: Path | None = None,
            at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """The signed report; raises ``ValueError`` when there is nothing trustworthy to re-run."""
    from opentine import _eval_verdict as ev
    from opentine._eval_dataset import dataset_digest
    from opentine._eval_run import read_verdicts, verify_eval
    from opentine._scorer_isolated import LIMITS, isolated
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    checked = verify_eval(Path(folder))
    if not checked["ok"]:
        raise ValueError(f"{folder} does not verify: re-score a verified eval")
    recorded = closure.read(Path(folder))
    verdicts = {row["item"]: row for row in read_verdicts(Path(folder))}
    data = dataset_digest(items)
    if {row["dataset"] for row in verdicts.values()} != {data}:
        raise ValueError("the dataset is not the one the eval scored")
    by_id = {item["id"]: item for item in items}
    pairs = []
    for name in sorted(verdicts):
        given = (outputs or {}).get(name, by_id[name])
        if "output" not in given:
            raise ValueError(f"item {name!r} has no output to re-score")
        pairs.append((by_id[name], given["output"]))
    limits = recorded.get("limits")
    if not isinstance(limits, dict) or set(limits) != set(LIMITS) or not all(
        isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in limits.values()
    ):  # fmt: skip
        limits = LIMITS
    files = list(inputs or [])
    if recorded["inputs"] and not files:
        raise ValueError("the eval was scored with --scorer-input files: pass them again")
    scorer = isolated(recorded["target"], inputs=files, limits=limits, lockfile=lockfile)
    if recorded.get("contract") is not None:
        scorer.config["contract"] = recorded["contract"]
    scores = scorer.batch(pairs)
    rows, agreed = [], 0
    for (item, _output), score in zip(pairs, scores):
        reported = verdicts[item["id"]]["score"]
        again = ev.score_text(score)
        agreed += again == reported
        rows.append({"item": item["id"], "reported": reported, "rescored": again,
                     "agree": again == reported})  # fmt: skip
    same = closure.closure_digest(recorded) == closure.closure_digest(scorer.config["closure"])
    doc: dict[str, Any] = {
        "convention": CONVENTION, "eval": checked["eval"], "dataset": data,
        "scorer_version": next(iter(verdicts.values()))["scorer_version"],
        "closure": closure.closure_digest(recorded),
        "rescored_closure": closure.closure_digest(scorer.config["closure"]),
        "closure_agree": same, "rows": rows, "agreed": agreed,
        "disagreed": len(rows) - agreed,
        "verdict": "agree" if same and agreed == len(rows) else "disagree",
        "isolation": scorer.config["closure"]["isolation"]["level"],
        "created_at": at or exp.now(),
    }  # fmt: skip
    from opentine import _signed_doc

    private = load_ed25519_private(key)
    doc["signer"] = key_fingerprint(private.public_key().public_bytes_raw())
    body = {n: doc[n] for n in FIELDS}
    doc["signature"] = _signed_doc.sign(
        DOMAIN, body, private, signer=doc["signer"], signed_at=doc["created_at"]
    )
    return doc


def verify_report(doc: Any) -> str | None:
    """None when *doc* is a rescore report signed by its named ``signer``."""
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION or set(FIELDS) - set(doc):
        return "not an opentine.rescore-report/1 document"
    return exp.verify(doc, DOMAIN, FIELDS)


__all__ = ["CONVENTION", "DOMAIN", "FIELDS", "rescore", "verify_report"]
