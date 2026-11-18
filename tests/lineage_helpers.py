"""Deterministic lineage folder for the 0.59 tests and the shared py/ts fixture.

``build_fixture(base)`` promotes RUN_B under the 0.58 gate, records a small
evolutionary archive over it, and returns ``tests/data/lineage_check.json``:
the lineage folder (path -> base64) and, per case, the ``(code, variant)``
pairs ``tine lineage check`` must report. ``ts/verifier/test/lineage.test.ts``
answers the same cases.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from opentine import _promote
from opentine._lineage import CONVENTION, record, variant_id
from opentine._lineage_check import check, read_folder
from opentine._promote_checks import load_policy
from opentine.attest_signing import sign_attestation
from tests.promote_helpers import (
    APPROVER,
    AT,
    PROMOTER,
    RUN_A,
    RUN_B,
    RUN_C,
    fingerprint,
    key,
    make_eval,
    policy,
)

RECORDER = "8d" * 32
UNKNOWN = "sha256:" + "e" * 64


def art(n: int) -> dict[str, str]:
    return {"code_tree": "sha256:" + hashlib.sha256(f"tree-{n}".encode()).hexdigest()}


def promoted(base: Path) -> tuple[Path, Path]:
    """RUN_B promoted over RUN_A: (decision.json, the candidate's eval folder)."""
    pol = load_policy(policy(base))
    signed = _promote.approve(key(APPROVER), RUN_B, "prod", state=base / "state", at=AT)
    (base / "approve.json").write_bytes(json.dumps(signed).encode())
    sides = [make_eval(base / n, r, f, dataset=d) for n, r, f, d in (
        ("base", RUN_A, lambda i: i % 2 == 0, "main"),
        ("cand", RUN_B, lambda i: i % 10 != 0, "main"),
        ("hbase", RUN_A, lambda i: i % 2 == 0, "hold"),
        ("hcand", RUN_B, lambda i: i % 10 != 0, "hold"))]  # fmt: skip
    _promote.promote(key(PROMOTER), pol, RUN_B, "prod", state=base / "state", out=base / "one",
                     baseline=sides[0], evals=sides[1], holdout=(sides[2], sides[3]),
                     approvals=[base / "approve.json"], at=AT)  # fmt: skip
    return base / "one" / "decision.json", sides[1]


def raw(store: Path, claim: dict, *, edit: dict | None = None) -> str:
    """Sign *claim* as-is (no checks), optionally edit it after signing."""
    full = {"convention": CONVENTION, "selector": "", "decision": None, "policy": None,
            "loop": None, "evals": [], "parents": [], "mutation_run": RUN_B, **claim}  # fmt: skip
    full["variant"] = variant_id(full["artifacts"])
    payload = {"claim": full, "evidence_ids": [], "signer": fingerprint(RECORDER),
               "target_id": full["mutation_run"]}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key(RECORDER), algorithm="ed25519",
                                            signed_at=AT)  # fmt: skip
    payload["claim"].update(edit or {})
    path = store / "variants" / f"{full['variant'][7:]}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())
    return full["variant"]


def archive(base: Path) -> tuple[Path, dict[str, str]]:
    """The lineage folder and the named variants in it."""
    decision, cand = promoted(base)
    store = base / "lineage"
    sign = key(RECORDER)
    v = {}
    v["root"] = record(sign, run=RUN_A, artifacts=art(0), store=store, at=AT)["variant"]
    v["good"] = record(sign, run=RUN_B, artifacts=art(1), store=store, parents=[v["root"]],
                       evals=[cand], decision=decision, selector="best-of-archive",
                       at=AT)["variant"]  # fmt: skip
    ev = json.loads((store / "variants" / f"{v['good'][7:]}.json").read_text())["claim"]["evals"]
    unsigned = base / "unsigned"
    unsigned.mkdir()
    rows = [json.loads(line) for line in (cand / "verdicts.jsonl").read_text().splitlines()]
    body = "".join(json.dumps({k: x for k, x in r.items() if k != "signature"}, sort_keys=True)
                   + "\n" for r in rows).encode()  # fmt: skip
    fake = "sha256:" + hashlib.sha256(b"unsigned-eval").hexdigest()
    (store / "evals" / f"{fake[7:]}.jsonl").write_bytes(body)
    v["unsigned"] = raw(store, {"artifacts": art(2), "parents": [v["root"]], "evals": [
        {"eval": fake, "verdicts_sha256": hashlib.sha256(body).hexdigest()}]})  # fmt: skip
    v["absent"] = raw(store, {"artifacts": art(3), "parents": [v["root"]], "evals": [
        {"eval": UNKNOWN, "verdicts_sha256": "0" * 64}]})  # fmt: skip
    v["no-eval"] = raw(store, {"artifacts": art(4), "parents": [v["root"]]})
    v["orphan"] = raw(store, {"artifacts": art(5), "parents": [UNKNOWN], "evals": ev})
    c1, c2 = variant_id(art(6)), variant_id(art(7))
    raw(store, {"artifacts": art(6), "parents": [c2], "evals": ev})
    v["cycle"] = raw(store, {"artifacts": art(7), "parents": [c1], "evals": ev})
    sha = json.loads((store / "variants" / f"{v['good'][7:]}.json").read_text())["claim"]
    v["wrong-decision"] = raw(store, {"artifacts": art(8), "parents": [v["good"]], "evals": ev,
                                      "decision": sha["decision"], "policy": "0" * 64})  # fmt: skip
    v["foreign-eval"] = raw(store, {"artifacts": art(11), "parents": [v["root"]], "evals": ev,
                                    "mutation_run": RUN_C})  # fmt: skip
    v["duplicate-key"] = raw(store, {"artifacts": art(12), "parents": [v["root"]], "evals": ev})
    dup = store / "variants" / f"{v['duplicate-key'][7:]}.json"
    text = dup.read_bytes().replace(b'"selector": ""', b'"selector": "hidden", "selector": ""')
    dup.write_bytes(text)
    v["tampered"] = raw(store, {"artifacts": art(9), "parents": [v["root"]], "evals": ev},
                        edit={"selector": "edited after signing"})  # fmt: skip
    v["merge"] = raw(store, {"artifacts": art(10), "parents": [v["good"], v["absent"]],
                             "evals": ev})  # fmt: skip
    v["unknown"] = UNKNOWN
    return store, v


def build_fixture(base: Path) -> dict:
    store, named = archive(base)
    files = read_folder(store)
    cases = []
    for name, variant in sorted(named.items()):
        found = check(files, variant)["findings"]
        cases.append({"id": name, "variant": variant,
                      "expect": [[f["code"], f["variant"]] for f in found]})  # fmt: skip
    return {"about": "0.59 lineage check cases (py and ts); regenerate with "
                     "python -m tests.test_059_lineage_fixture DIR",
            "files": {k: base64.b64encode(b).decode() for k, b in sorted(files.items())},
            "cases": cases}  # fmt: skip
