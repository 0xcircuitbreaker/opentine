"""``tine experiment check``: judge an experiment manifest offline (0.67).

Codes are ``tine experiment check`` codes, not ``tine verify`` codes (D12):

* ``fail:experiment.malformed`` - the manifest's fields are not the convention's;
* ``fail:experiment.unsigned`` / ``fail:experiment.bad-signature`` - the manifest
  carries no signature, or one that is not by its named signer;
* ``fail:experiment.reference-missing`` - a result row's verdict file is absent,
  unreadable, or not a ``tine-eval-verdict/1``;
* ``fail:experiment.reference-unsigned`` - the referenced verdict does not verify;
* ``fail:experiment.result-mismatch`` - the row's digest, score or passed differ
  from the referenced verdict;
* ``fail:experiment.key-separation`` - a verdict is signed by a key in the
  owner-pinned ``optimizer`` role;
* ``advisory:experiment.signer-unpinned`` - a verdict signer is not in a pinned
  ``scorer``/``eval``/``verdict`` role (blocks only with ``--strict``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine import _experiment as exp

VERDICT_ROLES = ("scorer", "eval", "verdict")


def _finding(level: str, code: str, row: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:experiment.{code}", "row": row,
            "message": message}  # fmt: skip


def roles(repo_path: str | Path | None) -> dict[str, Any]:
    """The owner-pinned roles (``_key_roles_pin``), or why there are none."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    if repo_path is None:
        return {"status": "absent", "roles": {}}
    store = Path(repo_path)
    store = store / ".tine" if (store / ".tine").is_dir() else store
    try:
        found = resolve(store)
    except KeyRoleError:
        return {"status": "unpinned", "roles": {}}
    pinned = found["status"] == "pinned"
    return {"status": found["status"], "roles": (found["roles"] or {}) if pinned else {}}


def _row(base: Path, row: dict[str, Any], pinned: dict[str, Any]) -> list[dict[str, Any]]:
    from opentine import _eval_verdict as ev

    rid = row["id"]
    try:
        verdict = json.loads((base / row["path"]).read_bytes())
        ev.body(verdict)
    except (OSError, ValueError, ev.EvalVerdictError) as exc:
        return [_finding("fail", "reference-missing", rid, f"{row['path']}: {exc}")]
    try:
        ev.verify(verdict)
    except ev.EvalVerdictError as exc:
        return [_finding("fail", "reference-unsigned", rid, f"{row['path']}: {exc.code}")]
    out: list[dict[str, Any]] = []
    got = ev.digest(verdict)
    if got != row["verdict"]:
        message = f"verdict digest is {got}, the row names {row['verdict']}"
        out.append(_finding("fail", "result-mismatch", rid, message))
    for name in ("score", "passed"):
        if verdict[name] != row[name]:
            out.append(_finding("fail", "result-mismatch", rid,
                                f"{name} is {verdict[name]!r} in the verdict, "
                                f"{row[name]!r} in the row"))  # fmt: skip
    signer = verdict["signer"]
    keys = pinned["roles"]
    if signer in keys.get("optimizer", []):
        out.append(_finding("fail", "key-separation", rid,
                            f"verdict signer {signer} holds the optimizer role"))  # fmt: skip
    elif not any(signer in keys.get(r, []) for r in VERDICT_ROLES):
        why = (
            "the verdict roles are unpinned (no owner-signed trust bundle)"
            if pinned["status"] != "pinned"
            else "not a pinned scorer/eval/verdict key"
        )
        out.append(_finding("advisory", "signer-unpinned", rid, f"{signer}: {why}"))
    return out


def check(path: str | Path, *, repo: str | Path | None = None,
          strict: bool = False) -> dict[str, Any]:  # fmt: skip
    """``{ok, experiment, manifest, signer, rows, findings}`` for the manifest at *path*."""
    doc = exp.load(path)
    found: list[dict[str, Any]] = []
    bad = exp.problems(doc)
    if bad:
        found.append(_finding("fail", "malformed", None, bad[0]))
    else:
        why = exp.verify(doc)
        if why == "unsigned":
            found.append(_finding("fail", "unsigned", None, "the manifest carries no signature"))
        elif why:
            found.append(_finding("fail", "bad-signature", None, why))
        pinned = roles(repo)
        base = Path(path).parent
        for row in doc["results"]:
            found += _row(base, row, pinned)
    fails = [f for f in found if f["level"] == "fail"]
    return {
        "ok": not fails and not (strict and found),
        "experiment": doc.get("experiment") if isinstance(doc.get("experiment"), str) else None,
        "manifest": exp.digest(doc),
        "signer": doc.get("signer") if isinstance(doc.get("signer"), str) else None,
        "rows": len(doc["results"]) if not bad else 0,
        "findings": found,
    }


__all__ = ["VERDICT_ROLES", "check", "roles"]
