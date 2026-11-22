"""A repository and record folder holding every record kind a self-improving loop writes.

Used by ``tests/test_080_verify_everywhere.py``. Records stored in the
repository go through their real writers (monitor verdicts, oversight
decisions, budget ledger entries, containment findings); admission records are
attestations under ``opentine.policy-admission/1``; the file-based records
(lineage variant, holdout commitment and access, promotion decisions for a
promote and a revert, the protected-surface pin) are signed with
``sign_attestation`` exactly as their writers sign them, under each kind's
claim convention.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine import _budget_ledger, _containment_records, _monitor_verdict, _oversight
from opentine._signing_pins import key_fingerprint
from opentine.attest_signing import sign_attestation
from opentine.repository import Repo
from opentine.repository._attest import attest
from tests.promote_helpers import key
from tests.query_helpers import add_run
from tests.query_helpers import claim as monitor_claim

AT = "2026-12-01T10:00:00Z"
DIGEST = "sha256:" + "d" * 64
SEEDS = {"monitor": "11" * 32, "approver": "22" * 32, "runner": "33" * 32,
         "policy": "44" * 32, "dataset": "55" * 32, "eval": "66" * 32}  # fmt: skip

#: Each record kind the reference loop produces, and where the fixture keeps it.
KINDS = ("lineage", "holdout", "monitor", "oversight", "admission", "budget", "containment",
         "promote", "revert")  # fmt: skip


def _fp(name: str) -> str:
    return key_fingerprint(key(SEEDS[name]).public_key().public_bytes_raw())


def _signed_file(path: Path, target: str, claim: dict[str, Any], signer: str) -> None:
    payload = {"claim": claim, "evidence_ids": [], "signer": _fp(signer), "target_id": target}
    payload["signature"] = sign_attestation(payload, key(SEEDS[signer]), algorithm="ed25519",
                                            signed_at=AT)  # fmt: skip
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _repo_records(repo: Repo, runs: list[str]) -> dict[str, str]:
    out = {"monitor": _monitor_verdict.record(repo, runs[0], monitor_claim("s1", "block"),
                                              key(SEEDS["monitor"]))}  # fmt: skip
    item = _oversight.promotion_item("prod", runs[1])
    out["oversight"] = _oversight.decide(repo, item, "approve", key(SEEDS["approver"]), at=AT)
    out["budget"] = _budget_ledger.append(
        repo, "loop:opt", "spend", {"run": runs[0], "cost": {"total_cost": 0.5}},
        key(SEEDS["runner"]), at_ms=1_800_000_000_000)  # fmt: skip
    finding = {"convention": "opentine.containment-finding/1", "run": runs[0], "at": AT}
    out["containment"] = _containment_records.record(
        repo, runs[0], finding, key(SEEDS["policy"]), f"containment:{runs[0]}")  # fmt: skip
    admission = {"convention": "opentine.policy-admission/1", "verificationResult": "PASSED",
                 "decision": "allow", "policy": {"name": "loop", "digest": DIGEST},
                 "subject": runs[1], "input_digest": DIGEST, "rules": [], "at": AT}  # fmt: skip
    signing = key(SEEDS["policy"])
    out["admission"] = attest(repo, runs[1], admission, signer=_fp("policy"), key=signing,
                              algorithm="ed25519", signed_at=AT)  # fmt: skip
    return out


def _file_records(folder: Path, runs: list[str]) -> None:
    hexes = [run.rsplit(":", 1)[-1] for run in runs]
    variant = {
        "convention": "opentine.lineage.variant",
        "variant": DIGEST,
        "artifacts": {"code_tree": DIGEST},
        "parents": [],
        "mutation_run": runs[1],
        "evals": [],
        "selector": None,
        "decision": None,
        "policy": None,
        "loop": "ref",
    }
    _signed_file(folder / "lineage" / "variants" / f"{hexes[1]}.json", runs[1], variant, "eval")
    commitment = {"convention": "opentine.holdout.commitment/1", "root": DIGEST, "count": 4}
    _signed_file(folder / "holdout" / "commitment.json", runs[0], commitment, "dataset")
    access = {"convention": "opentine.holdout.access/1", "run": runs[1], "at": AT}
    _signed_file(folder / "holdout" / "access" / f"{hexes[1]}.json", runs[1], access, "dataset")
    for action, run in (("promote", runs[1]), ("revert", runs[2])):
        decision = {"convention": "opentine.promotion-decision/1", "action": action,
                    "label": "prod", "candidate": run, "at": AT}  # fmt: skip
        _signed_file(folder / "promote" / f"{action}.json", run, decision, "approver")
    pin = {"convention": "opentine.integrity.protected/1", "files": {"grader.py": DIGEST}}
    _signed_file(folder / "integrity" / "protected.json", runs[0], pin, "policy")


def build(base: Path) -> dict[str, Any]:
    """``{"repo", "records", "runs", "oids"}``: a repository and its record folder."""
    repo = Repo.init(base / "repo")
    runs = [add_run(repo, f"gen{i}", cost=0.1 * (i + 1)) for i in range(3)]
    oids = _repo_records(repo, runs)
    _file_records(base / "records", runs)
    return {"repo": repo, "records": base / "records", "runs": runs, "oids": oids}
