"""``tine integrity``: the signed protected list, the run check and taint (0.60).

* **The list is pinned.** ``.tine/protected.toml`` counts only when an
  attestation in ``.tine/integrity/protected.json`` (an existing
  ``attestation``, Ed25519) has the claim
  ``{"schema": "opentine.integrity.protected/1", "protected_sha256": HEX}``
  over the file's bytes and is signed by a ``policy``-role key of
  ``.tine/key-roles.toml`` that is not an ``optimizer`` key (0.57 key roles).
  A loop that edits the list breaks the pin: ``fail:protected-list-unsigned``.
  No list at all is ``fail:protected-list-missing``.
* **Taint is a claim convention.** A run that tripped a ``fail:`` can be
  marked by an attestation on the run whose claim follows
  ``opentine.integrity.taint`` (``run``, ``codes``, ``findings_sha256``,
  ``protected_sha256``), filed as ``.tine/integrity/taints/HEX.json``.
  Any taint whose signature verifies counts: a taint only ever refuses.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._integrity import blocking, check, parse

LIST = Path(".tine") / "protected.toml"
PIN = Path(".tine") / "integrity" / "protected.json"
TAINTS = Path(".tine") / "integrity" / "taints"
LIST_SCHEMA = "opentine.integrity.protected/1"
TAINT = "opentine.integrity.taint"
MISSING = "fail:protected-list-missing"
UNSIGNED = "fail:protected-list-unsigned"


def _finding(code: str, detail: str, path: str = ".tine/protected.toml") -> dict[str, str]:
    return {"level": "fail", "code": code, "surface": "", "path": path, "detail": detail}


def _signer(doc: Any) -> str | None:
    from opentine._lineage import signed

    try:
        return doc["signer"] if signed(doc) else None
    except Exception:  # noqa: BLE001 - an unverifiable block is no signature
        return None


def _sign(key: Any, claim: dict[str, Any], target: str, at: str) -> dict[str, Any]:
    from opentine._promote import _who
    from opentine.attest_signing import sign_attestation

    payload = {"claim": claim, "evidence_ids": [], "signer": _who(key), "target_id": target}
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def _dump(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def sign_list(root: Path, key: Any, at: str) -> dict[str, Any]:
    """Sign the current list's bytes and file the pin; the list must parse."""
    raw = (Path(root) / LIST).read_bytes()
    parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    document = _sign(key, {"schema": LIST_SCHEMA, "protected_sha256": digest},
                     f"sha256:{digest}", at)  # fmt: skip
    _dump(Path(root) / PIN, document)
    return {"protected_sha256": digest, "signer": document["signer"],
            "pin": (Path(root) / PIN).as_posix()}  # fmt: skip


def load_list(root: Path) -> tuple[dict | None, str | None, list[dict[str, str]]]:
    """``(protected, sha256, findings)``: the list when its pin holds, else findings."""
    from opentine._integrity import ProtectedError
    from opentine._key_roles import KeyRoleError, load

    try:
        raw = (Path(root) / LIST).read_bytes()
    except FileNotFoundError:
        return None, None, [_finding(MISSING, "no .tine/protected.toml names the surfaces")]
    digest = hashlib.sha256(raw).hexdigest()
    try:
        protected = parse(raw)
        roles = load(Path(root) / ".tine" / "key-roles.toml") or {}
    except (ProtectedError, KeyRoleError) as exc:
        return None, digest, [_finding(UNSIGNED, str(exc))]
    allowed = set(roles.get("policy", [])) - set(roles.get("optimizer", []))
    try:
        doc = json.loads((Path(root) / PIN).read_bytes())
    except (OSError, ValueError):
        doc = None
    claim = doc.get("claim") if isinstance(doc, dict) else None
    good = (isinstance(claim, dict) and claim.get("schema") == LIST_SCHEMA
            and claim.get("protected_sha256") == digest)  # fmt: skip
    who = _signer(doc) if good else None
    if not allowed:
        why = "no policy-role key in .tine/key-roles.toml may pin the list"
    elif who is None:
        why = "no signed opentine.integrity.protected/1 attestation covers these bytes"
    elif who not in allowed:
        why = f"the list is signed by {who}, not a policy-role (non-optimizer) key"
    else:
        return protected, digest, []
    return None, digest, [_finding(UNSIGNED, why)]


def check_run(root: Path, run: str, *, strict: bool = False) -> dict[str, Any]:
    """``{ok, run, protected_sha256, touched, findings, blocking}`` for a stored run."""
    from opentine._integrity_observe import digests, touched

    protected, digest, findings = load_list(root)
    seen: list[dict[str, str]] = []
    if protected is not None:
        try:
            from opentine.repo import Repo

            seen = touched(Repo.open(root).load_run(run), Path(root))
        except Exception:  # noqa: BLE001 - not stored here: only the pins are judged
            seen = []
        findings = check(protected, {"touched": seen, "digests": digests(protected, root)})
    hard = blocking(findings, strict=strict)
    return {"ok": not hard, "run": run, "protected_sha256": digest, "touched": seen,
            "findings": findings, "blocking": len(hard), "taint": None}  # fmt: skip


def taint(root: Path, key: Any, row: dict[str, Any], at: str) -> dict[str, str]:
    """File the signed taint for a run whose check found a ``fail:``."""
    from opentine.kernel import canonical_json

    fails = [f for f in row["findings"] if f["level"] == "fail"]
    claim = {"convention": TAINT, "run": row["run"],
             "codes": sorted({f["code"] for f in fails}),
             "findings_sha256": hashlib.sha256(canonical_json(fails)).hexdigest(),
             "protected_sha256": row["protected_sha256"]}  # fmt: skip
    document = _sign(key, claim, row["run"], at)
    path = Path(root) / TAINTS / f"{row['run'].rsplit(':', 1)[-1]}.json"
    _dump(path, document)
    return {"path": path.as_posix(), "signer": document["signer"]}


def taints(root: Path | None, run: str) -> list[dict[str, Any]]:
    """The filed taints on *run* whose signature verifies (an empty list: none)."""
    if root is None or not isinstance(run, str) or ":" not in run:
        return []
    path = Path(root) / TAINTS / f"{run.rsplit(':', 1)[-1]}.json"
    try:
        doc = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return []
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not (isinstance(claim, dict) and claim.get("convention") == TAINT):
        return []
    if claim.get("run") != run or doc.get("target_id") != run or _signer(doc) is None:
        return []
    return [{"run": run, "codes": list(claim.get("codes") or []), "signer": doc["signer"]}]


def promote_refusals(root: Path | None, candidate: str) -> list[dict[str, str]]:
    """``promote.score-tainted`` for a filed taint, or a live ``fail:`` on the candidate."""
    from opentine._promote_checks import refusal

    if root is None:
        return []
    out = [refusal("promote.score-tainted",
                   f"{candidate} is tainted ({', '.join(t['codes'])}) by {t['signer']}")
           for t in taints(root, candidate)]  # fmt: skip
    if (Path(root) / LIST).is_file():
        row = check_run(root, candidate)
        codes = sorted({f["code"] for f in row["findings"] if f["level"] == "fail"})
        if codes:
            out.append(refusal("promote.score-tainted",
                               f"{candidate} trips {', '.join(codes)}"))  # fmt: skip
    return out


def lineage_findings(root: Path, files: dict[str, bytes], variants: list[str]) -> list[dict]:
    """``lineage.score-tainted`` for each variant whose mutation run is tainted."""
    from opentine._lineage import loads

    out = []
    for variant in variants:
        try:
            claim = loads(files[f"variants/{variant[7:]}.json"])["claim"]
            run = claim["mutation_run"]
        except (KeyError, TypeError, ValueError):
            continue
        for row in taints(root, run):
            out.append({"code": "lineage.score-tainted", "variant": variant,
                        "detail": f"mutation run {run} is tainted "
                                  f"({', '.join(row['codes'])})"})  # fmt: skip
    return out


__all__ = ["LIST", "MISSING", "PIN", "TAINT", "TAINTS", "UNSIGNED", "check_run",
           "lineage_findings", "load_list", "promote_refusals", "sign_list", "taint",
           "taints"]  # fmt: skip
