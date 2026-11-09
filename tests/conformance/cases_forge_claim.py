"""SPEC 4.19 forge claims (0.47): an upstream's ``.opentine/project``, never a pass.

The project is the 65-project family's first version (``_V0``): its digest is
the genesis the fingerprint is taken over. Only ``adapter_project`` answers.
"""

from __future__ import annotations

from opentine import _forge_claim, _project
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.cases_project import _V0, VERIFIER

GENESIS = _project.digest(_V0)
OTHER_GENESIS = "blob:sha256:" + "7" * 64
PROJECT = {"project_id": "app", "tenant": "acme", "genesis": GENESIS, "default_branch": "main"}
CLAIM = _forge_claim.build("app", "acme", GENESIS)


def _f(name, expect, intent, claim, reason=None, *, branch="main", project=None) -> Case:
    value = {"claim": claim, "branch": branch, "project": project or PROJECT}
    return Case(id=f"forge-claim.{name}", section="4.19", checklist=(8,),
                op="forge-claim.verify", profile=VERIFIER, expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


FORGE_CLAIM = Family(
    "72-forge-claim.json",
    "4.19",
    "forge-claim",
    (
        _f("match", ACCEPT, "the default branch claims this project: as mirrored, never a pass",
           CLAIM),
        _f("match-trunk", ACCEPT, "the default branch is whatever the slot names",
           CLAIM, branch="trunk", project={**PROJECT, "default_branch": "trunk"}),
        _f("wrong-id", REJECT, "a claim for another project id",
           {**CLAIM, "project_id": "other"}, "forge-claim.wrong-project"),
        _f("wrong-tenant", REJECT, "a claim for the same id under another tenant",
           {**CLAIM, "tenant": "evil"}, "forge-claim.wrong-project"),
        _f("wrong-fp", REJECT, "the same id, another project (a fork or a re-created one)",
           _forge_claim.build("app", "acme", OTHER_GENESIS), "forge-claim.wrong-fingerprint"),
        _f("missing", REJECT, "no .opentine/project on the default branch", None,
           "forge-claim.missing"),
        _f("non-default-branch-only", REJECT, "a claim only on a feature branch does not count",
           CLAIM, "forge-claim.not-default-branch", branch="feature/claim"),
        _f("extra-field", REJECT, "a field the claim format does not define",
           {**CLAIM, "owner": "someone"}, "forge-claim.malformed"),
        _f("signed", REJECT, "a claim is unsigned: its authority is the upstream itself",
           {**CLAIM, "signature": {"alg": "ed25519"}}, "forge-claim.malformed"),
        _f("bad-version", REJECT, "claim_version is 1",
           {**CLAIM, "claim_version": 2}, "forge-claim.malformed"),
        _f("bad-fingerprint", REJECT, "a fingerprint is sha256:<64 hex>",
           {**CLAIM, "fingerprint": "sha256:ABC"}, "forge-claim.malformed"),
    ),
)  # fmt: skip

FAMILIES = (FORGE_CLAIM,)
