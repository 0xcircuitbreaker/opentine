"""``promote --require-admission`` rebuilds the very input ``tine policy check`` signed.

The shipped ``promote`` policy reads signed evals (``--evals``), sealed
holdouts (``--holdout``), a budget (``--budget``) and the run's approvals; the
gate must assemble them the same way, or an allow from the check never counts.

These evals are not over the sealed holdout's items, so ``holdout-signed`` is
left out here; tests/test_076_holdout_digest.py runs the full shipped
``promote`` policy with a holdout eval. Everything else is the shipped policy.
"""

from __future__ import annotations

import json

import pytest

from opentine import _budget_ledger, _budget_policy, _containment, _oversight
from opentine._promote_admission import refusals
from opentine.repository import Repo
from tests.containment_fixture import POLICY, costed_run
from tests.holdout_helpers import ITEMS, tine
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import AT, fingerprint, key, make_eval, write_key

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"runner": "31" * 32, "policy": "32" * 32, "dataset": "1d" * 32, "eval": "2e" * 32,
         "a1": "41" * 32, "a2": "42" * 32}  # fmt: skip
SUBJECT = "loop:opt"


def _world(tmp_path, capsys):
    root = tmp_path / "repo"
    repo = Repo.init(root)
    roles = {"runner": [fingerprint(SEEDS["runner"])], "policy": [fingerprint(SEEDS["policy"])],
             "dataset": [fingerprint(SEEDS["dataset"])], "eval": [fingerprint(SEEDS["eval"])],
             "approver": [fingerprint(SEEDS["a1"]), fingerprint(SEEDS["a2"])]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    keys = {n: write_key(tmp_path / f"{n}.key", s).as_posix() for n, s in SEEDS.items()}
    run = repo.put_run(costed_run("subject", 0.5, 100)).run_id
    items = tmp_path / "items.jsonl"
    items.write_bytes(b"".join(json.dumps(i, sort_keys=True).encode() + b"\n" for i in ITEMS))
    folder = root / ".tine" / "holdouts" / "h1"
    code, _ = tine(capsys, "dataset", "seal", items.as_posix(), "--out", folder.as_posix(),
                   "--name", "h1", "--max-unseals", "2", "--max-items", "4", "--key",
                   keys["dataset"], "--seal-key", (tmp_path / "seal.key").as_posix(),
                   "--repo", root.as_posix(), "--at", AT, "--json")  # fmt: skip
    assert code == 0
    evals = make_eval(tmp_path / "evals", run, lambda i: True, n=4, signer=SEEDS["eval"])
    for name in ("a1", "a2"):
        bind = {"label": "prod", "candidate": run, "previous": None, "sequence": 0}
        _oversight.decide(repo, _oversight.promotion_item("prod", run), "approve",
                          key(SEEDS[name]), bind=bind, at=AT)  # fmt: skip
    doc = _budget_policy.build(SUBJECT, {"money_usd": 100.0}, serial=1, on_limit="deny",
                               issued_at=AT)  # fmt: skip
    _budget_ledger.append(repo, SUBJECT, "policy",
                          {"policy": _budget_policy.sign(doc, key(SEEDS["policy"]))},
                          key(SEEDS["runner"]), at_ms=1_700_000_000_000)  # fmt: skip
    _containment.record(repo, run, POLICY, key(SEEDS["runner"]))
    param = f"sandbox_digest={_containment.digest(POLICY)}"
    assembly = {"evals": [evals.as_posix()], "holdouts": [folder.as_posix()], "budget": SUBJECT}
    return root, run, keys, param, assembly


def _check(capsys, root, run, keys, policy, param, assembly):
    argv = ["policy", "check", policy, "--subject", run, "--param", param, "--key",
            keys["policy"], "--repo", root.as_posix(), "--json"]  # fmt: skip
    argv += [a for d in assembly["evals"] for a in ("--evals", d)]
    argv += [a for d in assembly["holdouts"] for a in ("--holdout", d)]
    argv += ["--budget", assembly["budget"]]
    code, body = tine(capsys, *argv)
    assert body["recorded"], body
    return body


def _promote_without_holdout(tmp_path):
    """The shipped ``promote`` policy minus ``holdout-signed`` (no holdout eval here)."""
    from opentine import _policy

    doc, _raw = _policy.load("promote")
    doc = {**doc, "name": "promote-no-holdout",
           "rules": [r for r in doc["rules"] if r["id"] != "holdout-signed"]}  # fmt: skip
    path = tmp_path / "promote-no-holdout.json"
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    return path.as_posix()


@pytest.mark.parametrize("policy", ["budget-within-cap", "k-of-n-approvals", "sandbox-digest",
                                    "no-integrity-fail", "promote"])  # fmt: skip
def test_the_shipped_policies_admit_through_the_gate(tmp_path, capsys, policy):
    root, run, keys, param, assembly = _world(tmp_path, capsys)
    if policy == "promote":
        policy = _promote_without_holdout(tmp_path)
    body = _check(capsys, root, run, keys, policy, param, assembly)
    assert body["decision"] == "allow", body["rules"]
    got = refusals(root, run, [policy], [param], evals=assembly["evals"],
                   holdouts=assembly["holdouts"], budget=assembly["budget"])  # fmt: skip
    assert got == []


def test_the_gate_without_the_check_assembly_does_not_count_the_allow(tmp_path, capsys):
    root, run, keys, param, assembly = _world(tmp_path, capsys)
    policy = _promote_without_holdout(tmp_path)
    assert _check(capsys, root, run, keys, policy, param, assembly)["decision"] == "allow"
    assert refusals(root, run, [policy], [param], **assembly) == []
    for drop in ({"evals": []}, {"holdouts": []}, {"budget": None}):
        kw = {**assembly, **drop}
        got = refusals(root, run, [policy], [param], **kw)
        assert [r["code"] for r in got] == ["promote.not-admitted"], drop


def test_promote_cli_accepts_the_assembly_flags():
    from opentine.cli import parse

    _parser, args = parse(
        ["promote", "R", "--baseline", "prod", "--require-admission", "promote",
         "--admission-evals", "E", "--admission-holdout", "H1", "--admission-holdout", "H2",
         "--admission-budget", SUBJECT])  # fmt: skip
    assert args.admission_evals == ["E"] and args.admission_holdout == ["H1", "H2"]
    assert args.admission_budget == SUBJECT
