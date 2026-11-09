"""Merge gates: signed VSAs, eval verdicts and human approvals (0.47, SPEC 4.19).

A gate policy (``opentine-merge-gates/1``, kept in the merge queue record) says
what a candidate run needs before it may land::

    {"format": "opentine-merge-gates/1",
     "vsa": {"key": "<b64url Ed25519>", "levels": [...], "policy": "", "resource": ""} | null,
     "evals": {"min": N, "signers": ["sha256:<fingerprint>", ...]} | null,
     "approvals": {"required": N, "keys": ["<hex Ed25519>", ...]} | null}

Evidence is ``{"vsa": [DSSE envelopes], "evals": [verdicts], "approvals":
[merge-approval records]}``. :func:`evaluate` checks each piece offline:

* **vsa** -- at least one envelope classifies ``valid`` for the candidate run
  under the pinned server key (:func:`opentine._vsa_verify.classify`).
* **evals** -- every verdict about the candidate verifies, none failed, at
  least ``min`` passed, each signed by a listed signer when ``signers`` is set.
* **approvals** -- at least ``required`` distinct listed keys signed an
  ``approve`` for this run and target; one ``reject`` from a listed key blocks.

Every piece that counted is named in the result's ``gates`` as ``{gate,
digest}`` (sha256 over JCS of the evidence), which the merge attestation signs.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from opentine.kernel import canonical_json

FORMAT = "opentine-merge-gates/1"


class GateError(ValueError):
    """A malformed gate policy."""


def digest(item: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(item)).hexdigest()


def check_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or policy.get("format") != FORMAT:
        raise GateError(f"a gate policy is an {FORMAT} object")
    if set(policy) - {"format", "vsa", "evals", "approvals"}:
        raise GateError("unknown gate policy field")
    vsa, evals, approvals = (policy.get(k) for k in ("vsa", "evals", "approvals"))
    if vsa is not None and (not isinstance(vsa, dict) or not isinstance(vsa.get("key"), str)):
        raise GateError("gates.vsa needs a pinned key")
    for name, value, count in (("evals", evals, "min"), ("approvals", approvals, "required")):
        if value is None:
            continue
        number = value.get(count) if isinstance(value, dict) else None
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise GateError(f"gates.{name}.{count} must be a positive count")
    if approvals is not None and not approvals.get("keys"):
        raise GateError("gates.approvals needs the approvers' keys")
    return policy


def _vsa(rule: dict[str, Any], rows: list[Any], run: str) -> tuple[list[str], list[str]]:
    from opentine._vsa_verify import classify

    key = rule["key"]
    raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    seen = []
    for envelope in rows:
        kind = classify(
            envelope,
            raw,
            run,
            levels=rule.get("levels") or (),
            policy=rule.get("policy") or "",
            resource=rule.get("resource") or "",
        )
        if kind == "valid":  # fmt: skip
            return [digest(envelope)], []
        seen.append(kind)
    return [], [f"vsa: no valid VSA for {run} ({', '.join(seen) or 'none given'})"]


def _evals(rule: dict[str, Any], rows: list[Any], run: str) -> tuple[list[str], list[str]]:
    from opentine._eval_verdict import EvalVerdictError, verify

    signers, passed, failures = rule.get("signers") or [], [], []
    for verdict in rows:
        try:
            found = verify(verdict)
        except EvalVerdictError as exc:
            failures.append(f"eval: {exc}")
            continue
        if found["run"] != run or (signers and found["signer"] not in signers):
            continue
        if not found["passed"]:
            failures.append(f"eval: item {found['item']} failed")
        else:
            passed.append(digest(verdict))
    if len(passed) < rule["min"]:
        failures.append(f"eval: {len(passed)} passing verdicts, {rule['min']} required")
    return (passed, []) if not failures else ([], failures)


def _approvals(
    rule: dict[str, Any], rows: list[Any], run: str, target: str
) -> tuple[list[str], list[str]]:
    from opentine._merge_record import check_approval
    from opentine._signed_record import RecordError

    keys, approvers, used, failures = set(rule["keys"]), set(), [], []
    for record in rows:
        block = record.get("signature") if isinstance(record, dict) else None
        key = block.get("public_key") if isinstance(block, dict) else None
        if key not in keys:
            continue
        try:
            found = check_approval(record, public_key=bytes.fromhex(key))
        except (RecordError, ValueError) as exc:
            failures.append(f"approval: {exc}")
            continue
        if found["run"] != run or found["target"] != target:
            continue
        if found["decision"] == "reject":
            failures.append(f"approval: rejected by {found['approver']}")
        elif key not in approvers:
            approvers.add(key)
            used.append(digest(record))
    if len(approvers) < rule["required"]:
        failures.append(f"approval: {len(approvers)} approvals, {rule['required']} required")
    return (used, []) if not failures else ([], failures)


def evaluate(policy: Any, evidence: Any, run: str, target: str) -> dict[str, Any]:
    """``{"ok", "gates": [{gate, digest}], "failures": [text]}`` for *run* onto *target*."""
    policy = check_policy(policy)
    evidence = evidence if isinstance(evidence, dict) else {}
    gates: list[dict[str, str]] = []
    failures: list[str] = []
    checks = (("vsa", lambda r, rows: _vsa(r, rows, run)),
              ("evals", lambda r, rows: _evals(r, rows, run)),
              ("approvals", lambda r, rows: _approvals(r, rows, run, target)))  # fmt: skip
    names = {"vsa": "vsa", "evals": "eval", "approvals": "approval"}
    for name, check in checks:
        rule = policy.get(name)
        if rule is None:
            continue
        rows = evidence.get(name)
        used, failed = check(rule, rows if isinstance(rows, list) else [])
        gates += [{"gate": names[name], "digest": d} for d in used]
        failures += failed
    return {"ok": not failures, "gates": gates if not failures else [], "failures": failures}


__all__ = ["FORMAT", "GateError", "check_policy", "digest", "evaluate"]
