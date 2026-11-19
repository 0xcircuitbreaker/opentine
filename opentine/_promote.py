"""``tine promote``: move a label only on signed evidence (0.58).

Every output is an existing kind. A promotion writes

* ``vsa.json``: the existing admission VSA (DSSE, ``verification_summary/v1``)
  over the candidate run, ``resourceUri`` ``tine://promotion/labels/LABEL``, the
  label's admission policy (``opentine.admission-policy``) as its policy, and
  every eval folder, approval and comparison as ``inputAttestations`` (the
  frozen-safe lineage: VSA evidence plus verdict references);
* ``decision.json``: an ``attestation`` on the candidate (tine-attest/2) whose
  claim follows ``opentine.promotion-decision/1`` (docs/EVALS-PROMOTION.md);
* ``compare.json`` (and ``holdout-compare.json``): the signed comparisons.

``--revert`` and a canary regression write only a decision (``action``
``revert``). The label's state lives in ``STATE/LABEL.json``: local state like
the merge queue's, not a wire format. A label moves only when the admission
policy covers ``labels/LABEL`` and lists the promoting key's fingerprint
among its ``subjects`` (when it names any).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._promote_checks import APPROVAL, DECISION, LABEL_RE, RUN_RE, gate, refusal

STATE = Path(".tine") / "promotion"
VERIFIER = "opentine:promote"


class PromotionRefused(ValueError):
    def __init__(self, refusals: list[dict[str, str]]) -> None:
        super().__init__("; ".join(f"{r['code']}: {r['detail']}" for r in refusals))
        self.refusals = refusals


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _who(key: Any) -> str:
    from opentine._signing_pins import key_fingerprint

    return key_fingerprint(key.public_key().public_bytes_raw())


def _sha(document: Any) -> str:
    from opentine.kernel import canonical_json

    return hashlib.sha256(canonical_json(document)).hexdigest()


def _write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def read_state(state: Path, label: str) -> dict[str, Any]:
    if not LABEL_RE.fullmatch(label):
        raise ValueError(f"label {label!r} must match [a-z0-9][a-z0-9._-]*")
    path = Path(state) / f"{label}.json"
    if path.is_file():
        return json.loads(path.read_text("utf-8"))
    return {"label": label, "current": None, "history": []}


def _check_label(policy: dict[str, Any], label: str, key: Any) -> None:
    rules = policy["admission"]
    if not rules.covers("promotion", f"labels/{label}"):
        raise PromotionRefused(
            [refusal("promote.label-policy", f"the admission policy does not cover labels/{label}")]
        )
    subjects = rules.rules.get("subjects")
    if subjects is not None and _who(key) not in subjects:
        raise PromotionRefused(
            [refusal("promote.label-policy", "the promoting key is not a subject of the policy")]
        )


def _decision(key: Any, candidate: str, claim: dict[str, Any], at: str) -> dict[str, Any]:
    from opentine.attest_signing import sign_attestation

    who = _who(key)
    payload = {"claim": {"schema": DECISION, **claim}, "evidence_ids": [], "signer": who,
               "target_id": candidate}  # fmt: skip
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def _move(state: Path, record: dict[str, Any], action: str, candidate: str | None,
          subject: str, decision: dict, at: str) -> None:  # fmt: skip
    record["history"].append({"action": action, "candidate": subject, "at": at,
                              "previous": record["current"],
                              "decision_sha256": _sha(decision)})  # fmt: skip
    record["current"] = candidate
    _write(Path(state) / f"{record['label']}.json", record)


def approve(key: Any, candidate: str, label: str, *, state: Path | None = None,
            at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """A signed approval on the candidate, bound to the label's holder and sequence."""
    from opentine.attest_signing import sign_attestation

    if not RUN_RE.fullmatch(candidate):
        raise ValueError("CANDIDATE must be a run:sha256: oid")
    record = read_state(state, label) if state is not None else {"current": None, "history": []}
    claim = {"schema": APPROVAL, "candidate": candidate, "label": label,
             "previous": record["current"], "sequence": len(record["history"])}  # fmt: skip
    payload = {"claim": claim,
               "evidence_ids": [], "signer": _who(key), "target_id": candidate}  # fmt: skip
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at or _now())}  # fmt: skip


def promote(key: Any, policy: dict[str, Any], candidate: str, label: str, *, state: Path,
            out: Path, baseline: Path, evals: Path, holdout: tuple[Path, Path] | None,
            approvals: list[Path], spent: str = "0", at: str | None = None,
            repo_path: Path | None = None, loop: str | None = None,
            policy_attestations: list[Path] = (),
            sealed_holdouts: list[Path] = (),
            canary_lengths: Path | None = None) -> dict:  # fmt: skip
    from opentine._eval_compare import attest
    from opentine.intoto import sign_statement
    from opentine.remote._vsa import build_vsa

    if not RUN_RE.fullmatch(candidate):
        raise ValueError("CANDIDATE must be a run:sha256: oid")
    at = at or _now()
    record = read_state(state, label)
    _check_label(policy, label, key)
    evidence, refusals = gate(policy, candidate=candidate, label=label, current=record["current"],
                              baseline=baseline, evals=evals, holdout=holdout,
                              approval_files=approvals, spent=spent,
                              promoter=_who(key), sequence=len(record["history"]))  # fmt: skip
    from opentine._promote_guards import guards
    from opentine._promote_pins import policy_pin

    pin, unsigned = policy_pin(repo_path, policy, _who(key), list(policy_attestations))
    from opentine._integrity_run import promote_refusals

    refusals = unsigned + guards(repo_path, _who(key), loop, candidate) + refusals
    refusals += promote_refusals(repo_path, candidate)
    from opentine._promote_holdout import refusals as sealed

    refusals += sealed(list(sealed_holdouts), canary_lengths, repo_path, candidate)  # 0.60
    from opentine._memory_quarantine import promote_refusals as memory

    refusals += memory(repo_path, candidate) if repo_path is not None else []  # 0.61
    if record["current"] == candidate:
        refusals.append(refusal("promote.already-current", f"{candidate} already holds {label}"))
    if refusals:
        raise PromotionRefused(refusals)
    inputs, files = [], {}
    if pin is not None:
        inputs.append({"uri": f"policy:{pin['signer']}", "digest": {"sha256": pin["sha256"]}})
    for name, side in evidence["evals"].items():
        inputs.append(
            {"uri": f"eval:{side['eval']}", "digest": {"sha256": side["verdicts_sha256"]}}
        )
    for row in evidence["approvals"]:
        inputs.append({"uri": f"approval:{row['approver']}", "digest": {"sha256": row["sha256"]}})
    for name in ("main", "holdout"):
        if evidence[name] is not None:
            files[name] = attest(evidence[name], key, signed_at=at)
            inputs.append({"uri": f"compare:{name}", "digest": {"sha256": _sha(files[name])}})
    statement = build_vsa("promotion", f"labels/{label}", candidate,
                          list(policy["admission"].rules["levels"]), verifier=VERIFIER,
                          policy=policy["admission"].descriptor(), time_verified=at)  # fmt: skip
    statement["predicate"]["inputAttestations"] = inputs
    vsa = sign_statement(statement, key)
    stats = {n: evidence[n]["stats"] for n in ("main", "holdout") if evidence[n] is not None}
    decision = _decision(key, candidate, {
        "action": "promote", "label": label, "candidate": candidate,
        "previous": record["current"], "vsa_sha256": _sha(vsa), "inputs": inputs,
        "stats": stats, "spent_usd": evidence["spent_usd"],
        "budget_usd": evidence["budget_usd"], "policy_sha256": policy["sha256"],
        "label_policy_sha256": policy["label_policy_sha256"], "policy_attestation": pin,
        "sequence": len(record["history"])}, at)  # fmt: skip
    _write(out / "vsa.json", vsa)
    _write(out / "decision.json", decision)
    for name, document in files.items():
        _write(out / ("compare.json" if name == "main" else "holdout-compare.json"), document)
    previous = record["current"]
    _move(state, record, "promote", candidate, candidate, decision, at)
    return {"action": "promote", "label": label, "candidate": candidate, "previous": previous,
            "current": candidate, "out": out.as_posix(), "inputs": inputs, "stats": stats,
            "refusals": []}  # fmt: skip


def revert(key: Any, policy: dict[str, Any], candidate: str, label: str, *, state: Path,
           out: Path, reason: str, stats: dict | None = None,
           at: str | None = None) -> dict:  # fmt: skip
    """The label goes back to the holder before *candidate*; a signed decision says why."""
    at = at or _now()
    record = read_state(state, label)
    _check_label(policy, label, key)
    if record["current"] != candidate:
        raise PromotionRefused(
            [refusal("promote.not-current", f"{candidate} does not hold {label}")]
        )
    promoted = [
        h for h in record["history"] if h["action"] == "promote" and h["candidate"] == candidate
    ]
    back = promoted[-1]["previous"] if promoted else None
    decision = _decision(key, candidate, {
        "action": "revert", "label": label, "candidate": candidate, "previous": back,
        "reason": reason, "stats": stats or {}}, at)  # fmt: skip
    _write(out / "decision.json", decision)
    _move(state, record, "revert", back, candidate, decision, at)
    return {"action": "revert", "label": label, "candidate": candidate, "previous": candidate,
            "current": back, "out": out.as_posix(), "reason": reason, "refusals": []}  # fmt: skip


def canary(key: Any, policy: dict[str, Any], candidate: str, label: str, *, state: Path,
           out: Path, baseline: Path, canary_evals: Path,
           at: str | None = None) -> dict:  # fmt: skip
    """Post-promotion canary: a signed, significant regression reverts the label."""
    from opentine._eval_compare import statistical
    from opentine._promote_checks import _eval

    refusals: list[dict[str, str]] = []
    _eval(canary_evals, policy, candidate, "canary candidate", refusals)
    record = read_state(state, label)  # the baseline is the holder the candidate replaced
    moved = [h for h in record["history"]
             if h["action"] == "promote" and h["candidate"] == candidate]  # fmt: skip
    _eval(baseline, policy, moved[-1]["previous"] if moved else None, "canary baseline", refusals,
          avoid=candidate)  # fmt: skip
    if refusals:
        raise PromotionRefused(refusals)
    row = statistical(baseline, canary_evals, method=policy["test"], alpha=policy["alpha"],
                      seed=policy["seed"], resamples=policy["resamples"])  # fmt: skip
    if row["stats"] is None:
        raise PromotionRefused([refusal("promote.eval-invalid", "the canary comparison failed")])
    if policy["metric"] not in row["stats"]["regressions"]:
        current = read_state(state, label)["current"]
        return {"action": "canary", "label": label, "candidate": candidate, "previous": current,
                "current": current, "out": out.as_posix(), "stats": {"canary": row["stats"]},
                "refusals": []}  # fmt: skip
    done = revert(key, policy, candidate, label, state=state, out=out, reason="canary-regression",
                  stats={"canary": row["stats"]}, at=at)  # fmt: skip
    return {**done, "stats": {"canary": row["stats"]}}


__all__ = ["STATE", "PromotionRefused", "approve", "canary", "promote", "read_state", "revert"]
