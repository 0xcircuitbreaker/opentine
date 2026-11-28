"""Judge, monitor and eval-item independence from a candidate's lineage (0.89).

A judge, a monitor or an eval item that comes from the candidate's own lineage
is not independent of it: a loop judged by a sibling variant's prompt, watched by
a monitor fine-tuned from its own weights, or scored on items its relatives
wrote drifts toward self-preference. :func:`check` joins the evidence:

* the candidate's *family* in the lineage folder (:mod:`opentine._lineage`): its
  ancestors, and every variant descended from one of them (siblings and
  cousins), found through signed variant records only; their artifact digests
  (code tree, prompt, config, weights, skill), variant ids, mutation runs and
  signer keys;
* optional digest ancestry (``{"child digest": ["parent digest", ...]}``, as
  custody ``derived-from`` links give it): a digest whose ancestry reaches the
  family is derived from it;
* optional prompt texts: a judge prompt whose similarity to a family prompt
  reaches the threshold (:func:`opentine._judge_ensemble.similarity`, default
  0.8) is a fork with small edits.

Findings (command-level codes of ``tine judge independence`` and of
``tine promote`` under ``judge_assurance = "required"``):

``fail:lineage.judge-not-independent``    a judge's prompt or rubric digest is a
                                          family artifact or derives from one, or
                                          its prompt is a near copy of a family prompt;
``fail:lineage.monitor-not-independent``  a monitor digest or probe checkpoint is
                                          a family artifact or derives from one;
``fail:lineage.self-generated-eval-item`` an item's ``generated_by`` (or
                                          ``metadata.generated_by``), ``{"run"|"variant"}``,
                                          names a family run or variant.

A variant record in the folder that does not parse or verify is
``fail:lineage.record-invalid``: editing a record (to drop a parent edge, say)
cannot hide a relative, it makes the family unknowable, and the check fails closed.

A judge's model is compared by name only, so each judge row records its
identity tier (``name``): hosted models with one name and different weights
cannot be told apart, and the check says so rather than claiming more.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

from opentine._judge_ensemble import THRESHOLD, similarity

MAX_DEPTH = 4096


def family(folder: Path, candidate: str) -> dict[str, Any]:
    """``{"variants", "runs", "digests", "signers", "known"}`` of *candidate*'s family.

    *candidate* is a variant id or a mutation run id; unsigned records are skipped.
    """
    from opentine import _lineage

    nodes: dict[str, dict[str, Any]] = {}
    invalid: list[str] = []
    folder = Path(folder)
    files = _lineage.read_folder(folder) if (folder / "variants").is_dir() else {}
    for name, raw in sorted(files.items()):
        if not name.startswith("variants/"):
            continue
        try:
            doc = _lineage.loads(raw)
        except (ValueError, RecursionError):
            invalid.append(name)
            continue
        claim = doc.get("claim") if isinstance(doc, dict) else None
        if not (isinstance(claim, dict) and isinstance(claim.get("variant"), str)
                and _lineage.signed(doc)):  # fmt: skip
            invalid.append(name)  # a record that does not verify hides nothing: reported
            continue
        arts = claim.get("artifacts") if isinstance(claim.get("artifacts"), dict) else {}
        parents = [p for p in claim.get("parents") or [] if isinstance(p, str)]
        node = nodes.setdefault(claim["variant"], {"parents": set(), "digests": set(),
                                                   "runs": set(), "signers": set()})  # fmt: skip
        node["parents"].update(parents)
        node["digests"].update(v for v in arts.values() if isinstance(v, str))
        if isinstance(claim.get("mutation_run"), str):
            node["runs"].add(claim["mutation_run"])
        if isinstance(doc.get("signer"), str):
            node["signers"].add(doc["signer"])
    start = {v for v, n in nodes.items() if v == candidate or candidate in n["runs"]}
    ancestors = _walk(start, lambda v: nodes.get(v, {}).get("parents", ()))
    children: dict[str, set[str]] = {}
    for v, n in nodes.items():
        for p in n["parents"]:
            children.setdefault(p, set()).add(v)
    members = _walk(ancestors, lambda v: children.get(v, ()))
    pick = [nodes[v] for v in members if v in nodes]
    return {"variants": sorted(members), "known": bool(start), "invalid": invalid,
            "runs": sorted({r for n in pick for r in n["runs"]}),
            "digests": sorted({d for n in pick for d in n["digests"]} | members),
            "signers": sorted({s for n in pick for s in n["signers"]})}  # fmt: skip


def _walk(start: set[str], step: Any) -> set[str]:
    seen, todo = set(start), list(start)
    while todo and len(seen) <= MAX_DEPTH * 16:
        for nxt in step(todo.pop()):
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return seen


def derived(digest: str, ancestry: dict[str, list[str]], targets: set[str]) -> bool:
    """Whether *digest* is in *targets* or its ancestry reaches one."""
    return bool(_walk({digest}, lambda d: ancestry.get(d, ())) & targets)


def _row(kind: str, ident: str, reasons: list[str], **more: Any) -> dict[str, Any]:
    return {"kind": kind, "id": ident, "independent": not reasons, "because": reasons, **more}


def _generated_by(item: Any) -> Any:
    if not isinstance(item, dict):
        return None
    meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return item.get("generated_by", meta.get("generated_by"))


def check(fam: dict[str, Any], *, judges: list[dict[str, Any]] = (),
          monitors: list[dict[str, Any]] = (), items: list[dict[str, Any]] = (),
          ancestry: dict[str, list[str]] | None = None, family_prompts: list[str] = (),
          threshold: Fraction = THRESHOLD) -> dict[str, Any]:  # fmt: skip
    """``{"rows", "findings"}``; *judges* are ``{"provenance", "prompt"?}``, *monitors*
    ``{"digest", "trusted"}``, *items* dataset rows."""
    digests, links = set(fam["digests"]), ancestry or {}
    rows, findings = [], []
    if fam.get("invalid") and (judges or monitors or items):
        findings.append({"code": "fail:lineage.record-invalid", "id": fam["invalid"][0],
                         "detail": f"{len(fam['invalid'])} variant record(s) do not verify, "
                                   "so the family cannot be known"})  # fmt: skip
    for judge in judges:
        doc, why = judge["provenance"], []
        for field in ("prompt_digest", "rubric_digest"):
            if doc.get(field) and derived(doc[field], links, digests):
                why.append(f"{field} is from the candidate lineage")
        text = judge.get("prompt")
        if text and any(similarity(text, p) >= threshold for p in family_prompts):
            why.append("the prompt is a near copy of a candidate-lineage prompt")
        name = judge.get("pin") or doc.get("prompt_digest")
        rows.append(_row("judge", name, why, model=doc.get("model"), identity_tier="name"))
        if why:
            findings.append({"code": "fail:lineage.judge-not-independent", "id": name,
                             "detail": "; ".join(why)})  # fmt: skip
    for monitor in monitors:
        why = ["the monitor is from the candidate lineage"] if derived(
            monitor["digest"], links, digests) else []  # fmt: skip
        rows.append(_row("monitor", monitor["digest"], why, trusted=monitor.get("trusted")))
        if why:
            findings.append({"code": "fail:lineage.monitor-not-independent",
                             "id": monitor["digest"], "detail": why[0]})  # fmt: skip
    runs = set(fam["runs"]) | set(fam["variants"])
    for item in items:
        made = _generated_by(item)
        named = {v for k, v in (made or {}).items() if k in ("run", "variant")} if isinstance(
            made, dict) else set()  # fmt: skip
        why = ["generated by the candidate lineage"] if named & runs else []
        ident = str(item.get("id")) if isinstance(item, dict) else "?"
        rows.append(_row("item", ident, why))
        if why:
            findings.append({"code": "fail:lineage.self-generated-eval-item", "id": ident,
                             "detail": f"generated_by {sorted(named & runs)}"})  # fmt: skip
    return {"rows": rows, "findings": findings}


__all__ = ["check", "derived", "family"]
