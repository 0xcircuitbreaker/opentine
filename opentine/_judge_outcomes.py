"""Signed judge outcomes (0.89): the ``opentine.judge-outcome/1`` convention.

``tine judge classify --key KEY --out FILE`` writes one signed document per
item, each an existing ``attestation`` shape whose claim is::

    {"schema": "opentine.judge-outcome/1", "judge": "jp1+sha256:<pin>",
     "item_sha256": "<hex of the canonical item>", "status": "label"|"abstain"|"error",
     "label": "<label>"|null}

``judge`` is the judge's provenance pin (:mod:`opentine._judge_provenance`), the
same ``scorer_version`` its eval verdicts carry, so an outcome cannot be filed
for another judge. The signer must be a pinned ``scorer`` key that is not an
``optimizer`` key (:func:`opentine._key_roles_pin.granting`). Label queues
(:mod:`opentine._label_ops`, ``tine label reveal``) and judge validation take
judge outcomes only in this form, never a plain file of labels.

:func:`parse` re-verifies every line when agreement is computed: a line that
does not verify, is signed by another key, names another judge, carries a
label outside the rubric, or names an item twice is an *error*. Neither an
abstention nor an error is ever scored as a label or as 0.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

CONVENTION = "opentine.judge-outcome/1"
ROLE = "scorer"
FIELDS = {"schema", "judge", "item_sha256", "status", "label"}
HEX_RE = re.compile(r"[0-9a-f]{64}")
_ERROR = object()


class OutcomeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def signers(store: Path) -> tuple[set[str], str]:
    from opentine._key_roles_pin import granting

    return granting(Path(store), ROLE)


def sign(key: Any, judge: str, item_sha256: str, outcome: dict[str, Any], at: str) -> dict:
    """One signed outcome document; an unknown status is signed as an error."""
    from opentine._integrity_run import _sign

    status = outcome.get("status") if isinstance(outcome, dict) else None
    if status not in ("label", "abstain"):
        status = "error"
    label = outcome.get("label") if status == "label" else None
    claim = {"schema": CONVENTION, "judge": judge, "item_sha256": item_sha256,
             "status": status, "label": label}  # fmt: skip
    return _sign(key, claim, f"sha256:{item_sha256}", at)


def _one(line: bytes, judge: str, keys: set[str], labels: list[str] | None) -> Any:
    """``(item, label | None | _ERROR)`` of one line, or ``None`` when no item is named."""
    from opentine import _json_shallow
    from opentine._integrity_run import _signer

    try:
        doc = _json_shallow.loads(line)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not isinstance(claim, dict) or not HEX_RE.fullmatch(str(claim.get("item_sha256"))):
        return None
    item = claim["item_sha256"]
    ok = (set(claim) == FIELDS and claim.get("schema") == CONVENTION
          and claim.get("judge") == judge and _signer(doc) in keys)  # fmt: skip
    if not ok:
        return item, _ERROR
    if claim["status"] == "abstain" and claim["label"] is None:
        return item, None
    good = isinstance(claim["label"], str) and (labels is None or claim["label"] in labels)
    return item, claim["label"] if claim["status"] == "label" and good else _ERROR


def parse(raw: bytes, judge: str, store: Path,
          labels: list[str] | None = None) -> tuple[dict[str, str | None], int]:  # fmt: skip
    """``({item_sha256: label, or None for an abstention}, errors)`` of signed outcome lines."""
    keys, _ = signers(store)
    answers: dict[str, list] = {}
    errors = 0
    for line in raw.split(b"\n"):
        if not line.strip():
            continue
        got = _one(line, judge, keys, labels)
        if got is None:
            errors += 1
        else:
            answers.setdefault(got[0], []).append(got[1])
    found = {}
    for item, given in answers.items():  # an item named twice is never one of its answers
        if len(given) == 1 and given[0] is not _ERROR:
            found[item] = given[0]
        else:
            errors += len(given)
    return found, errors


def check(raw: bytes, judge: str, store: Path) -> int:
    """The number of outcome lines; refuse a file with any line not signed for *judge*."""
    keys, why = signers(store)
    count = 0
    for number, line in enumerate(raw.split(b"\n"), 1):
        if not line.strip():
            continue
        got = _one(line, judge, keys, None)
        if got is None or (got[1] is _ERROR and not _signed_error(line, judge, keys)):
            raise OutcomeError("judge.outcome-unsigned", f"line {number} is not an outcome of "
                               f"{judge} signed by a pinned scorer key ({why})")  # fmt: skip
        count += 1
    if not count:
        raise OutcomeError("judge.outcome-unsigned", "no signed judge outcome")
    return count


def _signed_error(line: bytes, judge: str, keys: set[str]) -> bool:
    """A verified outcome whose status is ``error`` (kept: it lowers coverage)."""
    from opentine import _json_shallow
    from opentine._integrity_run import _signer

    doc = _json_shallow.loads(line)
    claim = doc["claim"]
    return (set(claim) == FIELDS and claim.get("schema") == CONVENTION
            and claim.get("judge") == judge and claim.get("status") == "error"
            and _signer(doc) in keys)  # fmt: skip


__all__ = ["CONVENTION", "OutcomeError", "ROLE", "check", "parse", "sign", "signers"]
