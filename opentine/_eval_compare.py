"""``tine eval compare --ci``: statistics over two evals, exported and attested (0.58).

The plain item-by-item diff (:func:`opentine._eval_run.compare`) gains, with
``--ci``, a ``stats`` block (:mod:`opentine._eval_stats`). ``--export FILE``
writes the export the numbers come from; ``scripts/eval_compare_reproduce.py
FILE`` reproduces ``stats`` from it exactly. ``--attest KEY --out FILE``
signs the result as an existing ``attestation`` (tine-attest, Ed25519) whose
claim follows the documented convention ``opentine.eval-compare/1``
(docs/EVALS-PROMOTION.md)::

    {"schema": "opentine.eval-compare/1", "a": EVAL, "b": EVAL,
     "export_sha256": HEX, "stats": {...}}

``target_id`` is eval B's id. No verifier reads the claim: it is reported
``unchecked`` (FREEZE.md ruling (b)); the envelope signature is checked as for
any attestation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from opentine import _eval_stats as stats
from opentine._eval_run import compare, read_verdicts
from opentine.kernel import canonical_json


def statistical(left: Path, right: Path, *, method: str, alpha: str, seed: int,
                resamples: int, public_key: bytes | None = None) -> dict[str, Any]:  # fmt: skip
    """The item diff plus ``stats``; the export rides along under ``export``."""
    stats.check(method, alpha, seed, resamples)
    row = compare(left, right, public_key=public_key)
    if not row["ok"]:
        return {**row, "stats": None, "export": None}
    data = stats.export(read_verdicts(left), read_verdicts(right), method=method,
                        alpha=alpha, seed=seed, resamples=resamples)  # fmt: skip
    data["a_eval"], data["b_eval"] = row["a"]["eval"], row["b"]["eval"]
    return {**row, "stats": stats.compute(data), "export": data}


def export_digest(data: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


def claim(row: dict[str, Any]) -> dict[str, Any]:
    return {"schema": stats.CONVENTION, "a": row["a"]["eval"], "b": row["b"]["eval"],
            "export_sha256": export_digest(row["export"]), "stats": row["stats"]}  # fmt: skip


def attest(row: dict[str, Any], private_key: Any, *, signed_at: str | None = None) -> dict:
    """A signed attestation over the comparison (target: eval B)."""
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation

    if row.get("stats") is None:
        raise ValueError("only a verified comparison with --ci can be attested")
    key = load_ed25519_private(private_key)
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    payload = {"claim": claim(row), "evidence_ids": [], "signer": signer,
               "target_id": row["b"]["eval"]}  # fmt: skip
    block = sign_attestation(payload, key, algorithm="ed25519", signed_at=signed_at)
    return {**payload, "signature": block}


__all__ = ["attest", "claim", "export_digest", "statistical"]
