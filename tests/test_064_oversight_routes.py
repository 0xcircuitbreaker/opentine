"""0.64: routing into tiers (monitor verdicts, threshold-crossing evals) and promote wiring."""

from __future__ import annotations

import json

import pytest

from opentine import _oversight, _oversight_gate, _oversight_policy
from opentine._promote_guards import late
from opentine.repository._holds import MONITOR_VERDICT, holds_path, read_holds
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_064_oversight_gate import AT, RUN, SEEDS, _approve, _key, repo  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

POLICY = b"""version = 1
[tiers.low]
k = 1
approvers = ["sha256:%s"]
[[route]]
source = "eval"
label = "prod*"
metric = "pass_rate"
above = 0.9
tier = "low"
[[route]]
source = "integrity"
tier = "low"
"""


def test_eval_routes_fire_only_across_the_threshold():
    policy = _oversight_policy.parse(POLICY % (b"a" * 64))
    item = {"source": "promotion", "label": "prod"}
    assert _oversight_policy.route(policy, {**item, "metrics": {"pass_rate": 0.95}}) == ["low"]
    assert _oversight_policy.route(policy, {**item, "metrics": {"pass_rate": 0.9}}) == []
    assert _oversight_policy.route(policy, {**item, "metrics": {}}) == []
    assert _oversight_policy.route(policy, {"source": "integrity"}) == ["low"]


@pytest.mark.parametrize(
    "text",
    [
        b"version = 1\n",
        b'version = 1\n[tiers.t]\nk = 3\napprovers = ["sha256:' + b"a" * 64 + b'"]\n',
        b'version = 1\n[tiers.t]\nk = 1\napprovers = ["x"]\n',
        b'version = 1\n[tiers.t]\nk = 1\napprovers = ["sha256:' + b"a" * 64 + b'"]\n'
        b'[[route]]\nsource = "eval"\ntier = "t"\nmetric = "pass_rate"\n',
    ],
)
def test_malformed_policies_are_refused(text):
    with pytest.raises(_oversight_policy.OversightError):
        _oversight_policy.parse(text)


def _verdict(store, action: str) -> str:
    claim = {"convention": "opentine.monitor-verdict/1",
             "monitor": {"id": "m", "kind": "rule", "model_digest": None},
             "input_digest": "sha256:" + "1" * 64,
             "reasoning": {"state": "unavailable", "digest": None}, "tool": "shell",
             "session": "s1", "score": 0.9, "threshold": 0.5, "action": action,
             "enforced": False, "mode": "advisory", "decided_by": "monitor", "latency_ms": 1,
             "deadline_ms": 100, "fail_closed": False,
             "trajectories": [{"role": "original", "digest": "sha256:" + "1" * 64}],
             "chosen": "original", "stop": None, "decided_at": AT}  # fmt: skip
    from opentine.core import Run

    run_id = store.put_run(Run(id="monitored", model_info="m")).run_id
    from opentine._monitor_verdict import record

    return record(store, run_id, claim, _key(SEEDS["monitor"]))


def test_a_flagged_monitor_verdict_is_queued_and_an_approval_clears_it(repo):  # noqa: F811
    oid = _verdict(repo, "block")
    item = f"monitor:{oid}"
    rows = {r["item"]: r for r in _oversight_gate.queue(repo)["items"]}
    assert rows[item]["state"] == "pending" and rows[item]["tiers"][0]["k"] == 2
    _oversight.decide(repo, item, "approve", _key(SEEDS["a2"]), at=AT)
    _oversight.decide(repo, item, "approve", _key(SEEDS["a3"]), at=AT)
    rows = {r["item"]: r for r in _oversight_gate.queue(repo)["items"]}
    assert rows[item]["state"] == "approved"
    assert _oversight_gate.queue(repo, from_objects=True) == _oversight_gate.queue(repo)


def test_a_verdict_outside_the_routed_actions_is_not_queued(repo):  # noqa: F811
    oid = _verdict(repo, "resample")  # held, but the route lists flag, defer and block
    assert oid in {r["oid"] for r in read_holds(holds_path(repo))
                   if r["target"].startswith(MONITOR_VERDICT)}  # fmt: skip
    assert all(r["item"] != f"monitor:{oid}" for r in _oversight_gate.queue(repo)["items"])


def test_promote_runs_the_oversight_gate(repo):  # noqa: F811
    record = {"current": None, "history": []}
    found = late(repo.path.parent, RUN, "prod", record, None)
    assert [r["code"] for r in found] == ["promote.oversight-insufficient"]
    _approve(repo, "a2")
    _approve(repo, "a3")
    assert late(repo.path.parent, RUN, "prod", record, None) == []
    assert json.dumps(found)
