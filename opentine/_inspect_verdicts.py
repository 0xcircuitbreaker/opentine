"""Inspect scores -> signed ``tine-eval-verdict/1`` eval folders (0.64).

One folder per scorer, the layout ``tine eval run`` writes (``eval.json`` +
``verdicts.jsonl``), so ``tine eval verify`` and ``tine eval compare`` read it
unchanged. A score value maps into 0..1: ``C``/``I``/``P``/``N`` (Inspect's
correct, incorrect, partial, no answer) to 1/0/0.5/0, a boolean to 1/0, a number
already in 0..1 to itself. Anything else (a dict, a list, a number outside
0..1, other text) gets no verdict and is listed under ``skipped``: the raw
value is still kept in the run annotation, so nothing is lost or guessed.

Dataset items are ``{"id", "input", "expected", "output", "run", "metadata"}``
with ``id`` the sample id (``<id>@<epoch>`` past epoch 1; a sample id that is not
1..256 safe characters becomes ``sample-<sha256 prefix>``).
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from opentine import _eval_verdict as verdicts
from opentine._eval_dataset import dataset_digest, item_digest
from opentine._eval_run import PINNED, SCHEMA, SUMMARY, VERDICTS, _tally, eval_id
from opentine._inspect_import import slug

LETTERS = {"C": 1, "I": 0, "P": Decimal("0.5"), "N": 0}


def score_value(value: Any) -> Decimal | int | None:
    """The 0..1 score for an Inspect value, or ``None`` when it has no such reading."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        return LETTERS.get(value)
    if isinstance(value, (int, float)) and 0 <= value <= 1:
        return Decimal(str(value))
    return None


def item_name(sample_id: Any, epoch: int) -> str:
    text = str(sample_id) if epoch == 1 else f"{sample_id}@{epoch}"
    if verdicts.NAME_RE.fullmatch(text):
        return text
    return hashed_name(sample_id, epoch)


def hashed_name(sample_id: Any, epoch: int) -> str:
    """A digest item name that keeps the id's JSON type (``1`` and ``"1"`` differ)."""
    return "sample-" + hashlib.sha256(json.dumps([sample_id, epoch]).encode()).hexdigest()[:24]


def _answer(output: dict[str, Any]) -> str:
    text = output.get("completion")
    return text if isinstance(text, str) else ""


def write_verdicts(rows: list[dict[str, Any]], key: Any, out_dir: Path, *,
                   threshold: float = 1.0, created_at: str) -> dict[str, Any]:  # fmt: skip
    """Sign one eval folder per scorer under *out_dir*; ``{scorer: summary}`` + skipped.

    *rows* are ``{"run", "sample": normalized sample}`` in log order.
    """
    from opentine._canon import atomic_write_text
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    private = load_ed25519_private(key)
    signer = key_fingerprint(private.public_key().public_bytes_raw())
    names = sorted({name for row in rows for name in row["sample"]["scores"]})
    summaries: dict[str, Any] = {}
    skipped: list[dict[str, Any]] = []
    folders = [slug(name, 64) for name in names]
    if len(set(folders)) != len(folders):
        raise ValueError("scorer names collide once made folder names; nothing written")
    for name in names:
        items, scored, taken = [], [], set()
        for row in rows:
            sample = row["sample"]
            if name not in sample["scores"]:
                continue
            raw = sample["scores"][name]
            value = score_value(raw.get("value") if isinstance(raw, dict) else raw)
            if value is None:
                skipped.append(
                    {"scorer": name, "sample_id": sample["id"], "epoch": sample["epoch"]}
                )
                continue
            ident_ = item_name(sample["id"], sample["epoch"])
            if ident_ in taken:  # 1 vs "1", or "a@2" vs ("a", epoch 2)
                ident_ = hashed_name(sample["id"], sample["epoch"])
            taken.add(ident_)
            item = {"id": ident_, "input": sample["input"],
                    "expected": sample["target"], "output": _answer(sample["output"]),
                    "run": row["run"], "metadata": {"inspect_sample_id": sample["id"],
                                                    "epoch": sample["epoch"]}}  # fmt: skip
            items.append(item)
            scored.append(value)
        if not items:
            continue
        scorer = "inspect-" + slug(name, 55)
        version = "inspect:" + slug(name, 150)
        pinned = {"dataset": dataset_digest(items), "scorer": scorer, "scorer_version": version,
                  "threshold": verdicts.score_text(threshold), "created_at": created_at,
                  "signer": signer}  # fmt: skip
        ident = eval_id(pinned)
        lines = []
        for item, value in zip(items, scored, strict=True):
            verdict = verdicts.make(
                private, eval=ident, dataset=pinned["dataset"], item=item["id"],
                item_digest=item_digest(item), run=item["run"], scorer=scorer,
                scorer_version=version, score=value, threshold=threshold, created_at=created_at,
            )  # fmt: skip
            lines.append(json.dumps(verdict, sort_keys=True, ensure_ascii=False) + "\n")
        folder = Path(out_dir) / slug(name, 64)
        folder.mkdir(parents=True, exist_ok=True)
        body = "".join(lines)
        atomic_write_text(folder / VERDICTS, body, newline="\n")
        sha = hashlib.sha256(body.encode()).hexdigest()
        summary = {"schema": SCHEMA, "eval": ident, **{k: pinned[k] for k in PINNED},
                   **_tally(lines), "verdicts_sha256": sha}  # fmt: skip
        atomic_write_text(
            folder / SUMMARY, json.dumps(summary, indent=2, sort_keys=True) + "\n", newline="\n"
        )
        summaries[name] = {"folder": folder.as_posix(), "eval": ident, "items": len(lines)}
    return {"scorers": summaries, "skipped": skipped}


__all__ = ["LETTERS", "item_name", "score_value", "write_verdicts"]
