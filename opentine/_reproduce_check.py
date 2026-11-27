"""``tine experiment check REPORT [--manifest M]``: judge a reproduce report (0.67).

A valid signature only says who wrote the report. The check also recomputes
what the signer could otherwise misstate:

* ``fail:experiment.bad-signature`` - not a report, or not signed by its signer;
* ``fail:experiment.report-mismatch`` - a row's ``delta``/``agree`` or the
  tallies/verdict do not follow from its observed scores and tolerance, repeated
  scores differ but ``score`` is not listed nondeterministic, or (with the
  manifest) the manifest digest, the seeded selection, a row's expected score or
  the manifest's own nondeterministic fields disagree;
* ``fail:experiment.key-separation`` - the report signer holds the pinned
  ``optimizer`` role (``--repo``);
* ``advisory:experiment.seed-override`` - the seed is not the manifest default;
* ``advisory:experiment.tolerance-chosen`` - a nonzero tolerance (the manifest
  declares none, so the reproducer picked it);
* ``advisory:experiment.single-repeat`` - one run per row cannot show score drift.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from opentine import _experiment as exp
from opentine import _reproduce
from opentine._experiment_check import _finding as _f


def _internal(doc: dict[str, Any]) -> list[str]:
    tol = Decimal(str(doc["tolerance"]))
    agreed = 0
    for row in doc["rows"]:
        scores = [Decimal(str(s)) for s in row["observed"]]
        if not scores or len(scores) != doc["repeats"]:
            return [f"row {row['id']}: {len(scores)} observed scores, repeats {doc['repeats']}"]
        delta = max(abs(s - Decimal(str(row["expected"]))) for s in scores)
        if Decimal(str(row["delta"])) != delta or row["agree"] is not (delta <= tol):
            return [f"row {row['id']}: delta {delta} and tolerance {tol} do not give its agree"]
        if len(set(scores)) > 1 and "score" not in doc["nondeterministic"]:
            return [f"row {row['id']}: repeats differ but score is not nondeterministic"]
        agreed += row["agree"]
    verdict = "agree" if agreed == len(doc["rows"]) else "disagree"
    if (doc["agreed"], doc["disagreed"], doc["verdict"]) != (
        agreed,
        len(doc["rows"]) - agreed,
        verdict,
    ):
        return ["agreed/disagreed/verdict do not follow from the rows"]
    if [r["id"] for r in doc["rows"]] != doc["selection"]["ids"]:
        return ["rows are not the selected ids"]
    return []


def _against(doc: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if exp.problems(manifest) or exp.verify(manifest):
        return [_f("fail", "report-mismatch", None, "the manifest is not a signed manifest")]
    if doc["manifest"] != exp.digest(manifest):
        return [_f("fail", "report-mismatch", None, "the report names another manifest")]
    sel = doc["selection"]
    if _reproduce.select(manifest, sel["k"], sel["seed"]) != sel:
        return [_f("fail", "report-mismatch", None, "selection is not the seeded sample")]
    out: list[dict[str, Any]] = []
    by_id = {r["id"]: r for r in manifest["results"]}
    for row in doc["rows"]:
        if row["expected"] != by_id[row["id"]]["score"]:
            out.append(_f("fail", "report-mismatch", row["id"], "expected is not the row score"))
    hidden = _reproduce.declared(manifest) - set(doc["nondeterministic"])
    if hidden:
        out.append(_f("fail", "report-mismatch", None,
                      f"manifest leaves {sorted(hidden)} nondeterministic"))  # fmt: skip
    if sel["seed"] != _reproduce.default_seed(manifest):
        out.append(_f("advisory", "seed-override", None, f"seed {sel['seed']} is not the default"))
    return out


def check_report(doc: dict[str, Any], *, manifest: str | Path | None = None,
                 roles: dict[str, Any] | None = None) -> list[dict[str, Any]]:  # fmt: skip
    """The findings for the reproduce report *doc*."""
    why = _reproduce.verify_report(doc)
    if why:
        return [_f("fail", "bad-signature", None, why)]
    try:
        bad = _internal(doc)
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        bad = [f"malformed report: {exc!r}"]
    found = [_f("fail", "report-mismatch", None, m) for m in bad]
    if not bad and manifest is not None:
        found += _against(doc, exp.load(manifest))
    if doc["signer"] in ((roles or {}).get("roles") or {}).get("optimizer", []):
        found.append(_f("fail", "key-separation", None, "report signer holds the optimizer role"))
    if not bad and Decimal(str(doc["tolerance"])) != 0:
        found.append(_f("advisory", "tolerance-chosen", None,
                        f"tolerance {doc['tolerance']} was chosen by the reproducer"))  # fmt: skip
    if doc.get("repeats") == 1:
        found.append(_f("advisory", "single-repeat", None, "one run per row hides score drift"))
    return found


__all__ = ["check_report"]
