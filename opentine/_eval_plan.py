"""``tine eval plan`` / ``tine eval reveal``: a signed analysis plan with a committed seed (0.86).

A plan is an existing ``attestation`` (tine-attest/2, Ed25519) whose target is
the dataset digest and whose claim follows ``opentine.eval-plan/1``
(docs/EVAL-PLANS.md)::

    {"schema": "opentine.eval-plan/1", "dataset": "sha256:HEX",
     "metric": "score" | "pass_rate", "reducer": "mean" | "pass@k" | "pass^k",
     "epochs": N, "test": "paired-bootstrap" | "permutation", "alpha": "0.05",
     "resamples": R, "correction": "holm" | "bonferroni", "max_candidates": M,
     "cluster_key": null | "FIELD", "mde": "0.05", "min_coverage": "1",
     "seed_commitment": "sha256:HEX"}

``seed_commitment`` is SHA-256 over a 32-byte secret the plan's signer keeps.
After the runs, a reveal (claim ``opentine.eval-plan-reveal/1``: ``plan_sha256``
and the secret in hex) opens it, and the analysis seed is derived from the
secret and the plan's digest, so nobody who lacks the secret can pick or
predict it, and re-running the analysis cannot change it.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

PLAN = "opentine.eval-plan/1"
REVEAL = "opentine.eval-plan-reveal/1"
SEED_DOMAIN = "opentine.eval-plan-seed/1:"
METRICS = ("score", "pass_rate")
REDUCERS = ("mean", "pass@k", "pass^k")
TESTS = ("paired-bootstrap", "permutation")
CORRECTIONS = ("holm", "bonferroni")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
HEX_RE = re.compile(r"[0-9a-f]{64}")
FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
FIELDS = ("schema", "dataset", "metric", "reducer", "epochs", "test", "alpha", "resamples",
          "correction", "max_candidates", "cluster_key", "mde", "min_coverage",
          "seed_commitment")  # fmt: skip


class PlanError(ValueError):
    """A plan or reveal that does not hold; ``code`` is the ``promote.*`` reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fraction(value: Any, name: str, *, low_open: bool) -> str:
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{name} {value!r} is not a decimal") from exc
    if not number.is_finite() or number > 1 or number < 0 or (low_open and number == 0):
        raise ValueError(f"{name} must be in {'(0' if low_open else '[0'}, 1]")
    return f"{number.normalize():f}"


def _count(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def check(claim: dict[str, Any]) -> dict[str, Any]:
    """The plan claim, every field checked (raises ``ValueError``)."""
    if not isinstance(claim, dict) or claim.get("schema") != PLAN or set(claim) != set(FIELDS):
        raise ValueError(f"a plan claim has exactly the {PLAN} fields")
    if not (isinstance(claim["dataset"], str) and DIGEST_RE.fullmatch(claim["dataset"])):
        raise ValueError("dataset must be sha256: + 64 lower hex")
    for name, allowed in (("metric", METRICS), ("reducer", REDUCERS), ("test", TESTS),
                          ("correction", CORRECTIONS)):  # fmt: skip
        if claim[name] not in allowed:
            raise ValueError(f"{name} is one of {', '.join(allowed)}")
    epochs = _count(claim["epochs"], "epochs", 1, 100)
    if claim["reducer"] != "mean" and epochs < 2:
        raise ValueError(f"reducer {claim['reducer']} needs epochs >= 2")
    _count(claim["resamples"], "resamples", 100, 100_000)
    _count(claim["max_candidates"], "max_candidates", 1, 10_000_000)
    key = claim["cluster_key"]
    if key is not None and not (isinstance(key, str) and FIELD_RE.fullmatch(key)):
        raise ValueError("cluster_key is null or an item field name")
    alpha = _fraction(claim["alpha"], "alpha", low_open=True)
    if Decimal(alpha) >= 1:
        raise ValueError("alpha must be strictly between 0 and 1")
    for name in ("alpha", "mde", "min_coverage"):
        if _fraction(claim[name], name, low_open=name != "min_coverage") != claim[name]:
            raise ValueError(f"{name} must be a canonical decimal string")
    if not (isinstance(claim["seed_commitment"], str)
            and DIGEST_RE.fullmatch(claim["seed_commitment"])):  # fmt: skip
        raise ValueError("seed_commitment must be sha256: + 64 lower hex")
    return claim


def new_secret() -> str:
    return secrets.token_hex(32)


def commitment(secret_hex: str) -> str:
    if not (isinstance(secret_hex, str) and HEX_RE.fullmatch(secret_hex)):
        raise ValueError("the plan secret is 64 lower-case hex characters")
    return "sha256:" + hashlib.sha256(bytes.fromhex(secret_hex)).hexdigest()


def derive_seed(secret_hex: str, plan_sha256: str) -> int:
    """The analysis seed: SHA-256 over the domain, the secret and the plan digest, 53 bits
    (an exact integer in every JSON reader)."""
    raw = hashlib.sha256(f"{SEED_DOMAIN}{secret_hex}:{plan_sha256}".encode("ascii")).digest()
    return int.from_bytes(raw[:8], "big") >> 11


def _sign(private: Any, claim: dict[str, Any], target: str, at: str) -> dict[str, Any]:
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation

    key = load_ed25519_private(private)
    who = key_fingerprint(key.public_key().public_bytes_raw())
    payload = {"claim": claim, "evidence_ids": [], "signer": who, "target_id": target}
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def make_plan(private: Any, fields: dict[str, Any], secret_hex: str, at: str) -> dict[str, Any]:
    claim = check({"schema": PLAN, **fields, "seed_commitment": commitment(secret_hex)})
    return _sign(private, claim, claim["dataset"], at)


def file_sha256(doc: dict[str, Any]) -> str:
    """What a reveal and a promotion bind: SHA-256 over the plan's JCS."""
    from opentine.kernel import canonical_json

    return hashlib.sha256(canonical_json(doc)).hexdigest()


def make_reveal(private: Any, plan: dict[str, Any], secret_hex: str, at: str) -> dict[str, Any]:
    opened = opened_plan(plan)
    if commitment(secret_hex) != opened["claim"]["seed_commitment"]:
        raise PlanError("promote.seed-not-committed", "the secret does not open the commitment")
    claim = {"schema": REVEAL, "plan_sha256": file_sha256(plan), "secret": secret_hex}
    return _sign(private, claim, opened["claim"]["dataset"], at)


def _opened(doc: Any, schema: str) -> tuple[dict[str, Any], str, str]:
    from opentine._promote_pins import _who

    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not isinstance(claim, dict) or claim.get("schema") != schema:
        raise PlanError("promote.plan-invalid", f"not an {schema} attestation")
    who = _who(doc)
    if who is None:
        raise PlanError("promote.plan-invalid", f"the {schema} signature does not verify")
    at = doc["signature"].get("signed_at")
    if not isinstance(at, str):
        raise PlanError("promote.plan-invalid", f"the {schema} carries no signing time")
    return claim, who, at


def opened_plan(doc: Any) -> dict[str, Any]:
    """``{claim, signer, signed_at, sha256}`` of a verified plan (raises :class:`PlanError`)."""
    claim, who, at = _opened(doc, PLAN)
    try:
        check(claim)
    except ValueError as exc:
        raise PlanError("promote.plan-invalid", str(exc)) from exc
    if doc.get("target_id") != claim["dataset"]:
        raise PlanError("promote.plan-invalid", "a plan's target is its dataset")
    return {"claim": claim, "signer": who, "signed_at": at, "sha256": file_sha256(doc)}


def opened_reveal(doc: Any, plan: dict[str, Any]) -> int:
    """The derived seed, once the reveal opens *plan*'s commitment under the plan's signer."""
    claim, who, _at = _opened(doc, REVEAL)
    if claim.get("plan_sha256") != plan["sha256"]:
        raise PlanError("promote.seed-not-committed", "the reveal names another plan")
    if who != plan["signer"]:
        raise PlanError("promote.seed-not-committed", "the reveal is not the plan signer's")
    secret = claim.get("secret")
    try:
        opens = commitment(secret) == plan["claim"]["seed_commitment"]
    except ValueError:
        opens = False
    if not opens:
        raise PlanError("promote.seed-not-committed", "the secret does not open the commitment")
    return derive_seed(secret, plan["sha256"])


def load(path: Path) -> Any:
    from opentine._json_shallow import loads, unique_pairs

    return loads(Path(path).read_bytes().decode("utf-8"), object_pairs_hook=unique_pairs)


def dump(path: Path, doc: Any) -> None:
    from opentine._canon import atomic_write_text

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(Path(path), json.dumps(doc, indent=2, sort_keys=True) + "\n", newline="\n")


__all__ = ["CORRECTIONS", "PLAN", "REDUCERS", "REVEAL", "PlanError", "check", "commitment",
           "derive_seed", "dump", "file_sha256", "load", "make_plan", "make_reveal",
           "new_secret", "opened_plan", "opened_reveal"]  # fmt: skip
