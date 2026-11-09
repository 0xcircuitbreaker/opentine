"""SPEC 4.19: run merge and pick, merge attestations and merge approvals (0.47).

``merge.compute`` and ``merge.pick`` pin the deterministic oids: the same two
run payloads (and flattened trees) give the same merge event and merge run in
every implementation. ``merge.verify`` and ``merge-approval.verify`` check the
signed records with the published keys (HMAC and Ed25519 are deterministic and
every record fixes its time). Only the ops in ``adapter_merge`` answer.
"""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _merge_record
from opentine._merge import merge_payloads, run_oid
from opentine.kernel import ObjectEnvelope
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

READER, VERIFIER = "reader", "verifier"
WHEN = "2026-11-09T00:00:00Z"
_HMAC_A = KEYS["hmac_a"].hex()


def _private(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _public(name: str) -> str:
    return _private(name).public_key().public_bytes_raw().hex()


def _blob(text: str) -> str:
    return ObjectEnvelope.create("blob", text.encode()).oid


def _payload(name: str, *parents: str) -> dict:
    return {"causal_ids": [], "kind": "think", "output_blob": _blob(name),
            "parent_ids": list(parents), "time_unix": 1}  # fmt: skip


def _event(name: str, *parents: str) -> str:
    return ObjectEnvelope.create("event", _payload(name, *parents)).oid


def _run(events: list[str], roots: list[str], tips: list[str], **extra) -> dict:
    return {"created_at": 1794100000, "events": events,
            "manifests": {"policy": _blob("{}")}, "roots": roots, "status": "completed",
            "tips": tips, **extra}  # fmt: skip


E0 = _event("base")
A1, B1 = _event("ours", E0), _event("theirs", E0)
B2 = _event("theirs-2", B1)
X0, Y0 = _event("x"), _event("y")
BASE = _run([E0], [E0], [E0])
OURS = _run([E0, A1], [E0], [A1], forked_from=run_oid(BASE))
THEIRS = _run([E0, B1, B2], [E0], [B2], created_at=1794100000.25, forked_from=run_oid(BASE))
F1, F2, F3 = _blob("one"), _blob("two"), _blob("three")


def _leaf(oid: str, mode: str = "100644") -> dict:
    return {"mode": mode, "oid": oid}


TREE_BASE = {"a.txt": _leaf(F1), "dir/b.txt": _leaf(F1)}


def _c(name, expect, intent, ours, theirs, trees=None, reason=None) -> Case:
    return Case(id=f"merge.compute.{name}", section="4.19", checklist=(8,), op="merge.compute",
                profile=READER, expect=expect, intent=intent,
                input=V({"ours": ours, "theirs": theirs, "trees": trees}),
                reason=reason)  # fmt: skip


def _picked(name: str) -> dict:
    return {"causal_ids": [], "kind": "tool", "output_blob": _blob(name), "parent_ids": [B1],
            "time_unix": 2}  # fmt: skip


def _p(name, expect, intent, ours, picks, reason=None) -> Case:
    return Case(id=f"merge.pick.{name}", section="4.19", checklist=(8,), op="merge.pick",
                profile=READER, expect=expect, intent=intent,
                input=V({"ours": ours, "picks": picks}), reason=reason)  # fmt: skip


_P1 = _picked("p1")
_P1_OID = ObjectEnvelope.create("event", _P1).oid
_P2 = {**_picked("p2"), "causal_ids": [_P1_OID]}

COMPUTE = (
    _c("diverged", ACCEPT, "two forks of one run: shared events once, one merge event",
       OURS, THEIRS),
    _c("swapped", ACCEPT, "the same runs the other way round give another merge (ours first)",
       THEIRS, OURS),
    _c("theirs-ahead", ACCEPT, "a tip the other side continues is no leaf of the union",
       BASE, THEIRS),
    _c("disjoint", ACCEPT, "two unrelated runs: both roots kept",
       _run([X0], [X0], [X0]), _run([Y0], [Y0], [Y0], created_at=7)),
    _c("ours-a-merge", ACCEPT, "ours' own parents and forked_from are not copied",
       {**OURS, "parents": [run_oid(BASE), run_oid(_run([X0], [X0], [X0]))]}, THEIRS),
    _c("trees-clean", ACCEPT, "each side changed another path: a clean three-way tree",
       OURS, THEIRS, {"base": TREE_BASE, "ours": {**TREE_BASE, "a.txt": _leaf(F2)},
                      "theirs": {**TREE_BASE, "dir/c/d.txt": _leaf(F3, "100755")}}),
    _c("trees-delete", ACCEPT, "a path deleted on one side and unchanged on the other goes",
       OURS, THEIRS, {"base": TREE_BASE, "ours": {"a.txt": _leaf(F1)}, "theirs": TREE_BASE}),
    _c("trees-same-change", ACCEPT, "identical changes on both sides are no conflict",
       OURS, THEIRS, {"base": TREE_BASE, "ours": {**TREE_BASE, "a.txt": _leaf(F3)},
                      "theirs": {**TREE_BASE, "a.txt": _leaf(F3)}}),
    _c("trees-conflict", ACCEPT, "both sides changed a.txt: a recorded conflict, run paused",
       OURS, THEIRS, {"base": TREE_BASE, "ours": {**TREE_BASE, "a.txt": _leaf(F2)},
                      "theirs": {**TREE_BASE, "a.txt": _leaf(F3)}}),
    _c("trees-no-base", ACCEPT, "with no base tree, a path both sides added differently "
       "conflicts", OURS, THEIRS, {"base": None, "ours": {"n": _leaf(F2)},
                                   "theirs": {"n": _leaf(F3), "m": _leaf(F1)}}),
    _c("trees-one-side", ACCEPT, "a tree on one side only: no merged tree", OURS, THEIRS,
       {"base": None, "ours": TREE_BASE, "theirs": None}),
    _c("policy-conflict", ACCEPT, "a differing policy manifest is a conflict",
       OURS, {**THEIRS, "manifests": {"policy": _blob('{"x":1}')}}),
    _c("same-run", REJECT, "a run cannot be merged with itself", OURS, copy.deepcopy(OURS),
       reason="merge.same-run"),
    _c("up-to-date", REJECT, "theirs already inside ours: nothing to merge", THEIRS, BASE,
       reason="merge.up-to-date"),
    _c("no-events", REJECT, "a run without events", OURS, _run([], [], []),
       reason="merge.malformed"),
    _c("tips-outside", REJECT, "tips must be events of the run", OURS,
       _run([B1], [B1], [B2]), reason="merge.malformed"),
    _c("bad-path", REJECT, "a tree path may not climb out", OURS, THEIRS,
       {"base": None, "ours": {"../x": _leaf(F1)}, "theirs": {}}, "merge.malformed"),
    _c("file-and-dir", REJECT, "a file on one side where the other has a directory",
       OURS, THEIRS, {"base": None, "ours": {"d": _leaf(F1)}, "theirs": {"d/e": _leaf(F2)}},
       "merge.malformed"),
    _c("bad-mode", REJECT, "a leaf is a file, an executable or a link", OURS, THEIRS,
       {"base": None, "ours": {"d": _leaf(F1, "40000")}, "theirs": {}}, "merge.malformed"),
)  # fmt: skip

PICK = (
    _p("one", ACCEPT, "one event of another run onto ours' tip", OURS, [[_P1_OID, _P1]]),
    _p("chain", ACCEPT, "a causal link to an earlier pick follows its copy", OURS,
       [[_P1_OID, _P1], [ObjectEnvelope.create("event", _P2).oid, _P2]]),
    _p("held", REJECT, "an event already in the run", OURS, [[A1, _payload("ours", E0)]],
       "merge.malformed"),
    _p("not-its-oid", REJECT, "a payload that is not the event it claims to be", OURS,
       [[B1, _P1]], "merge.malformed"),
    _p("none", REJECT, "a pick of nothing", OURS, [], "merge.malformed"),
    _p("twice", REJECT, "the same event picked twice", OURS, [[_P1_OID, _P1], [_P1_OID, _P1]],
       "merge.malformed"),
)  # fmt: skip

# --- the signed records ------------------------------------------------------ #

_MERGED = merge_payloads(OURS, THEIRS)
_PARENTS = [run_oid(OURS), run_oid(THEIRS)]
_GATES = [{"gate": "approval", "digest": "sha256:" + "a" * 64},
          {"gate": "eval", "digest": "sha256:" + "b" * 64}]  # fmt: skip


def _record(**fields) -> dict:
    return {"kind": _merge_record.KIND, "merge_version": 1, "run": _MERGED["run_oid"],
            "parents": _PARENTS, "target": "heads/main", "fencing": 3, "gates": _GATES,
            "conflicts": 0, "actor": "worker-1", "merged_at": WHEN, **fields}  # fmt: skip


def _approval(**fields) -> dict:
    return {"kind": _merge_record.APPROVAL_KIND, "approval_version": 1,
            "run": run_oid(THEIRS), "target": "heads/main", "decision": "approve",
            "approver": "alice@example", "approved_at": WHEN, **fields}  # fmt: skip


def _signed(sign, body: dict, kind: str) -> dict:
    if kind == "hmac":
        return sign(body, KEYS["hmac_a"], algorithm="hmac-sha256", key_id="vector",
                    signed_at=WHEN)  # fmt: skip
    return sign(body, _private(kind), algorithm="ed25519", key_id="vector", signed_at=WHEN)


def _edited(record: dict, **fields) -> dict:
    out = copy.deepcopy(record)
    out.update(fields)
    return out


def _v(name, expect, intent, record, reason=None, *, hmac=None, public=None, run=None) -> Case:
    value = {"record": record, "hmac_key_hex": hmac, "public_key": public, "run": run}
    return Case(id=f"merge.verify.{name}", section="4.19", checklist=(8,), op="merge.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


def _a(name, expect, intent, record, reason=None, *, hmac=None, public=None) -> Case:
    value = {"record": record, "hmac_key_hex": hmac, "public_key": public}
    return Case(id=f"merge-approval.verify.{name}", section="4.19", checklist=(8,),
                op="merge-approval.verify", profile=VERIFIER, expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


_M_HMAC = _signed(_merge_record.sign, _record(), "hmac")
_M_ED = _signed(_merge_record.sign, _record(), "ed25519_seed")
_M_FF = _signed(_merge_record.sign, _record(target=None, fencing=None, gates=[]), "hmac")
_A_ED = _signed(_merge_record.sign_approval, _approval(), "ed25519_seed")
_A_NO = _signed(_merge_record.sign_approval, _approval(decision="reject"), "ed25519_seed")
_RUN = _MERGED["run"]

VERIFY = (
    _v("valid-hmac", ACCEPT, "an HMAC merge attestation verifies under its key", _M_HMAC,
       hmac=_HMAC_A),
    _v("valid-ed25519-trusted", ACCEPT, "an Ed25519 attestation under the trusted key", _M_ED,
       public=_public("ed25519_seed")),
    _v("valid-ed25519-tofu", ACCEPT, "with no key, an attestation on its embedded key", _M_ED),
    _v("valid-with-run", ACCEPT, "the merged run hashes to the record's run, same parents",
       _M_ED, run=_RUN),
    _v("valid-no-queue", ACCEPT, "a merge outside a queue: no target, fencing or gates",
       _M_FF, hmac=_HMAC_A),
    _v("other-run", REJECT, "a merged run other than the one signed", _M_ED,
       "merge.run-mismatch", run=THEIRS),
    _v("parents-swapped", REJECT, "the run's parents differ from the record's",
       _signed(_merge_record.sign, _record(run=run_oid({**_RUN, "parents": _PARENTS[::-1]}),
                                           parents=_PARENTS), "hmac"),
       "merge.run-mismatch", hmac=_HMAC_A, run={**_RUN, "parents": _PARENTS[::-1]}),
    _v("fencing-edited", REJECT, "a fencing token raised after signing",
       _edited(_M_HMAC, fencing=4), "merge.bad-signature", hmac=_HMAC_A),
    _v("gate-dropped", REJECT, "a gate removed after signing", _edited(_M_ED, gates=_GATES[:1]),
       "merge.bad-signature"),
    _v("wrong-key", REJECT, "an Ed25519 attestation by a key other than the trusted one",
       _M_ED, "merge.wrong-key", public=_public("ed25519_seed_b")),
    _v("hmac-key-ed25519-record", REJECT, "a supplied HMAC key never falls back to TOFU",
       _M_ED, "merge.wrong-key", hmac=_HMAC_A),
    _v("no-key", REJECT, "an HMAC attestation with no key cannot verify", _M_HMAC,
       "merge.no-key"),
    _v("unsigned", REJECT, "an attestation without a signature", _record(), "merge.unsigned",
       hmac=_HMAC_A),
    _v("one-parent", REJECT, "a merge has two or more parents",
       _edited(_M_HMAC, parents=_PARENTS[:1]), "merge.malformed", hmac=_HMAC_A),
    _v("self-parent", REJECT, "a merge cannot be its own parent",
       _edited(_M_HMAC, parents=[_MERGED["run_oid"], _PARENTS[1]]), "merge.malformed",
       hmac=_HMAC_A),
    _v("bad-gate", REJECT, "a gate is vsa, eval or approval",
       _edited(_M_HMAC, gates=[{"gate": "vibes", "digest": "sha256:" + "c" * 64}]),
       "merge.malformed", hmac=_HMAC_A),
    _v("bad-time", REJECT, "merged_at is RFC 3339 UTC to the second",
       _edited(_M_HMAC, merged_at="2026-11-09"), "merge.malformed", hmac=_HMAC_A),
    _v("extra-field", REJECT, "a field the format does not define",
       _edited(_M_HMAC, note="x"), "merge.malformed", hmac=_HMAC_A),
    _v("wrong-version", REJECT, "a merge_version other than 1",
       _edited(_M_HMAC, merge_version=2), "merge.malformed", hmac=_HMAC_A),
    _a("valid", ACCEPT, "an approval under the approver's key", _A_ED,
       public=_public("ed25519_seed")),
    _a("valid-reject", ACCEPT, "a signed rejection verifies too (the gate then blocks)",
       _A_NO, public=_public("ed25519_seed")),
    _a("run-edited", REJECT, "an approval moved to another run after signing",
       _edited(_A_ED, run=_MERGED["run_oid"]), "merge-approval.bad-signature"),
    _a("decision-edited", REJECT, "a rejection turned into an approval",
       _edited(_A_NO, decision="approve"), "merge-approval.bad-signature"),
    _a("wrong-key", REJECT, "an approval by a key other than the approver's", _A_ED,
       "merge-approval.wrong-key", public=_public("ed25519_seed_b")),
    _a("unsigned", REJECT, "an approval without a signature", _approval(),
       "merge-approval.unsigned"),
    _a("bad-decision", REJECT, "a decision is approve or reject",
       _edited(_A_ED, decision="maybe"), "merge-approval.malformed"),
    _a("no-target", REJECT, "an approval names its target ref",
       _edited(_A_ED, target=""), "merge-approval.malformed"),
)  # fmt: skip

MERGE = Family("68-merge.json", "4.19", "merge", (*COMPUTE, *PICK, *VERIFY))

FAMILIES = (MERGE,)
