"""``holdout-signed`` matches an eval to a sealed holdout by dataset digest.

A sealed holdout's signed commitment records the dataset digest of its items
(``dataset``, the same ``sha256:`` digest ``tine eval`` puts on each verdict).
An eval counts as a holdout eval when its verdicts' ``dataset`` equals the
digest a verified holdout, signed by a pinned ``dataset`` key, records. The
full shipped ``promote`` policy then admits a run whose records satisfy it, and
each condition removed denies on exactly its rule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _budget_ledger, _budget_policy, _containment, _oversight
from opentine._eval_dataset import dataset_digest
from opentine._eval_run import run_eval
from opentine._eval_scorers import parse
from opentine._promote_admission import refusals
from opentine.repository import Repo
from tests.containment_fixture import POLICY, costed_run
from tests.holdout_helpers import ITEMS, tine
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import AT, fingerprint, key, make_eval, write_key

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"runner": "31" * 32, "policy": "32" * 32, "dataset": "1d" * 32, "eval": "2e" * 32,
         "a1": "41" * 32, "a2": "42" * 32, "rogue": "55" * 32}  # fmt: skip
SUBJECT = "loop:opt"
RULES = ["holdout-signed", "no-integrity-fail", "k-of-n-approvals", "budget-within-cap",
         "sandbox-digest"]  # fmt: skip


def _holdout_eval(out: Path, run: str, items: list[dict]) -> Path:
    outputs = {i["id"]: {"output": i["expected"], "run": run} for i in items}
    run_eval(items, parse("exact"), key(SEEDS["eval"]), out, outputs=outputs, created_at=AT)
    return out


def _world(tmp_path, capsys, *, approvers=("a1", "a2"), seal_seed="dataset"):
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
    if seal_seed == "dataset":
        code, _ = tine(capsys, "dataset", "seal", items.as_posix(), "--out", folder.as_posix(),
                       "--name", "h1", "--max-unseals", "2", "--max-items", "4", "--key",
                       keys["dataset"], "--seal-key", (tmp_path / "seal.key").as_posix(),
                       "--repo", root.as_posix(), "--at", AT, "--json")  # fmt: skip
        assert code == 0
    else:  # a commitment signed by a key that holds no pinned dataset role
        from opentine import _holdout

        folder.mkdir(parents=True)
        _holdout.seal(list(ITEMS), folder, name="h1", key=key(SEEDS[seal_seed]),
                      master=b"\x07" * 32, at=AT,
                      budget={"max_unseals": 2, "max_items": 4})  # fmt: skip
    evals = _holdout_eval(tmp_path / "evals", run, list(ITEMS))
    for name in approvers:
        bind = {"label": "prod", "candidate": run, "previous": None, "sequence": 0}
        _oversight.decide(repo, _oversight.promotion_item("prod", run), "approve",
                          key(SEEDS[name]), bind=bind, at=AT)  # fmt: skip
    doc = _budget_policy.build(SUBJECT, {"money_usd": 100.0}, serial=1, on_limit="deny",
                               issued_at=AT)  # fmt: skip
    _budget_ledger.append(repo, SUBJECT, "policy",
                          {"policy": _budget_policy.sign(doc, key(SEEDS["policy"]))},
                          key(SEEDS["runner"]), at_ms=1_700_000_000_000)  # fmt: skip
    _containment.record(repo, run, POLICY, key(SEEDS["runner"]))
    params = [f"sandbox_digest={_containment.digest(POLICY)}", "label=prod"]
    assembly = {"evals": [evals.as_posix()], "holdouts": [folder.as_posix()], "budget": SUBJECT}
    return root, run, keys, params, assembly


def _check(capsys, root, run, keys, policy, params, assembly):
    argv = ["policy", "check", policy, "--subject", run, "--key", keys["policy"],
            "--repo", root.as_posix(), "--json"]  # fmt: skip
    argv += [a for p in params for a in ("--param", p)]
    argv += [a for d in assembly["evals"] for a in ("--evals", d)]
    argv += [a for d in assembly["holdouts"] for a in ("--holdout", d)]
    if assembly["budget"]:
        argv += ["--budget", assembly["budget"]]
    _code, body = tine(capsys, *argv)
    assert body["recorded"], body
    return body


def _failed(body) -> list[str]:
    return sorted(r["id"] for r in body["rules"]
                  if r["effect"] == "require" and r["outcome"] != "true")  # fmt: skip


def test_the_seal_records_the_dataset_digest(tmp_path, capsys):
    from opentine._holdout import load

    root, _run, _keys, _params, assembly = _world(tmp_path, capsys)
    claim = load(Path(assembly["holdouts"][0]))["claim"]
    assert claim["dataset"] == dataset_digest(list(ITEMS))


def test_a_signed_eval_over_the_sealed_dataset_satisfies_holdout_signed(tmp_path, capsys):
    root, run, keys, params, assembly = _world(tmp_path, capsys)
    body = _check(capsys, root, run, keys, "holdout-signed", params, assembly)
    assert body["decision"] == "allow", body["rules"]


def test_a_different_dataset_digest_is_not_a_holdout_eval(tmp_path, capsys):
    root, run, keys, params, assembly = _world(tmp_path, capsys)
    other = make_eval(tmp_path / "other", run, lambda i: True, n=4, signer=SEEDS["eval"])
    assembly = {**assembly, "evals": [other.as_posix()]}
    body = _check(capsys, root, run, keys, "holdout-signed", params, assembly)
    assert body["decision"] == "deny" and _failed(body) == ["holdout-signed"]


def test_a_holdout_not_signed_by_a_pinned_dataset_key_does_not_count(tmp_path, capsys):
    root, run, keys, params, assembly = _world(tmp_path, capsys, seal_seed="rogue")
    body = _check(capsys, root, run, keys, "holdout-signed", params, assembly)
    assert body["decision"] == "deny" and _failed(body) == ["holdout-signed"]


def test_a_forged_commitment_does_not_count(tmp_path, capsys):
    root, run, keys, params, assembly = _world(tmp_path, capsys)
    path = Path(assembly["holdouts"][0]) / "commitment.json"
    doc = json.loads(path.read_bytes())
    doc["claim"]["dataset"] = "sha256:" + "0" * 64
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    body = _check(capsys, root, run, keys, "holdout-signed", params, assembly)
    assert body["decision"] == "deny" and _failed(body) == ["holdout-signed"]


def test_the_full_shipped_promote_policy_admits(tmp_path, capsys):
    root, run, keys, params, assembly = _world(tmp_path, capsys)
    body = _check(capsys, root, run, keys, "promote", params, assembly)
    assert body["decision"] == "allow", body["rules"]
    assert refusals(root, run, ["promote"], params, **assembly) == []


def _drop(rule, tmp_path, capsys):
    if rule == "k-of-n-approvals":
        world = _world(tmp_path, capsys, approvers=("a1",))
    else:
        world = _world(tmp_path, capsys)
    root, run, keys, params, assembly = world
    if rule == "holdout-signed":
        assembly = {**assembly, "holdouts": []}
    elif rule == "no-integrity-fail":
        (root / ".tine" / "protected.toml").write_bytes(b"")  # an unsigned protected list
    elif rule == "budget-within-cap":
        assembly = {**assembly, "budget": None}
    elif rule == "sandbox-digest":
        params = ["sandbox_digest=sha256:" + "0" * 64, "label=prod"]
    return root, run, keys, params, assembly


@pytest.mark.parametrize("rule", RULES)
def test_removing_one_condition_denies_on_exactly_that_rule(tmp_path, capsys, rule):
    root, run, keys, params, assembly = _drop(rule, tmp_path, capsys)
    body = _check(capsys, root, run, keys, "promote", params, assembly)
    assert body["decision"] == "deny" and _failed(body) == [rule], body["rules"]
    got = refusals(root, run, ["promote"], params, **assembly)
    assert [r["code"] for r in got] == ["promote.not-admitted"]
