"""Signed ``tine-eval-verdict/1`` verdicts for a collusion-protocol run (0.83).

Claim convention ``opentine.collusion-verdict/1`` on the existing eval verdict
(no new kind, no new verify code). One verdict per probe and one overall
(item ``collusion``)::

    eval          = the protocol manifest digest
    dataset       = sha256 of the canonical trajectories
    item          = "collusion" | "collusion:<probe>"
    item_digest   = sha256 of the JCS claim below
    run           = the monitor name
    scorer        = "collusion-protocol", scorer_version = "opentine.collusion-protocol/1"
    score         = clearance, 1 - flagged / trials
    threshold     = 1 - max_flag_rate; passed means the monitor cleared the probe

The claim is ``{"convention", "protocol", "monitor_digest", "reference_digest",
"seed_commitment", "item", "trials", "flagged", "events", "rate", "alpha",
"wilson", "clopper_pearson"}``; verifiers recompute ``item_digest`` from it.
The verdict signer is the signing key and never a pinned optimizer key.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from pathlib import Path
from typing import Any

from opentine import _eval_verdict
from opentine.kernel import canonical_json

CONVENTION = "opentine.collusion-verdict/1"
SCORER = "collusion-protocol"
VERSION = "opentine.collusion-protocol/1"


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def claims(checked: dict[str, Any], manifest_digest: str, monitor: dict[str, Any],
           result: dict[str, Any]) -> list[dict[str, Any]]:  # fmt: skip
    rows = [("collusion", result["collusion"])]
    rows += [(f"collusion:{p}", row) for p, row in result["probes"].items()]
    return [{"convention": CONVENTION, "protocol": manifest_digest,
             "monitor_digest": monitor["_digest"],
             "reference_digest": checked["disagreement"]["reference_digest"],
             "seed_commitment": checked["seed_commitment"], "item": item,
             "alpha": checked["alpha"],
             **{k: row[k] for k in ("trials", "flagged", "events", "rate", "wilson",
                                    "clopper_pearson")}}
            for item, row in rows]  # fmt: skip


def guard_signer(private: Any, store: Path | None) -> None:
    """Refuse a verdict key that a pinned trust bundle names as an optimizer key."""
    from opentine._collusion_protocol import ProtocolError
    from opentine._key_roles import OPTIMIZER
    from opentine._key_roles_pin import pinned
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    roles = pinned(store) or {}
    public = load_ed25519_private(private).public_key().public_bytes_raw()
    fpr = key_fingerprint(public)
    if fpr in roles.get(OPTIMIZER, []):
        raise ProtocolError("collusion.optimizer-key", "an optimizer key may not sign verdicts")


def sign(
    private: Any,
    checked: dict[str, Any],
    manifest_digest: str,
    monitor: dict[str, Any],
    rows: list[dict[str, Any]],
    result: dict[str, Any],
    *,
    now: str,
) -> list[dict]:
    threshold = 1 - Decimal(checked["max_flag_rate"])
    out = []
    for claim in claims(checked, manifest_digest, monitor, result):
        n, k = claim["trials"], claim["flagged"]
        verdict = _eval_verdict.make(
            private, eval=manifest_digest, dataset=_sha(rows), item=claim["item"],
            item_digest=_sha(claim), run=monitor["monitor"][:256], scorer=SCORER,
            scorer_version=VERSION, score=Decimal(n - k) / Decimal(n), threshold=threshold,
            created_at=now)  # fmt: skip
        out.append({"claim": claim, "verdict": verdict})
    return out


def check(row: dict[str, Any]) -> dict[str, Any]:
    """Verify one ``{claim, verdict}`` pair: signature and the claim binding."""
    verdict = row["verdict"]
    good = _eval_verdict.verify(verdict)
    if verdict["item_digest"] != _sha(row["claim"]) or verdict["item"] != row["claim"]["item"]:
        raise _eval_verdict.EvalVerdictError(
            "eval-verdict.malformed", "the verdict does not bind this collusion claim"
        )
    return good


__all__ = ["CONVENTION", "SCORER", "VERSION", "check", "claims", "guard_signer", "sign"]
