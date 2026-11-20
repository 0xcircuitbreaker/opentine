"""0.69 end to end: the three containment acceptance criteria on one repository.

1. Every run records a signed sandbox policy digest, and a mismatch with the
   declared policy fails ``tine containment check`` (``sandbox-policy-mismatch``).
2. A simulated probe run that copies itself, fetches weights and spawns a
   process is flagged; the findings are held, listed in the oversight queue
   and visible in ``tine query``.
3. An over-budget agent is denied on the very next action (counted in steps,
   not time), and a limit raise it signs itself is refused, routed to oversight
   and visible in ``tine query`` with the ledger.

No wall clock, no network: the clock is injected and the probes are recorded
text, except one harmless child process inside ``tmp_path``.
"""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from opentine import (
    _budget_gate,
    _budget_status,
    _containment,
    _containment_detect,
    _oversight_policy,
    _oversight_queue,
)
from tests.containment_fixture import POLICY, probe_run
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_070_budget_ledger import (  # noqa: F401
    SUBJECT,
    T0,
    _apply,
    _key,
    _policy,
    _run,
    _spend,
    _tine,
    repo,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _query(capsys, where: str, sql: str) -> dict:
    assert _tine(capsys, "query", "index", "--rebuild", "--repo", where)[0] == 0
    code, body = _tine(capsys, "query", sql, "--repo", where, "--verify", "--json")
    assert code == 0, body
    return body


def test_policy_digest_probes_and_budget_end_to_end(repo, tmp_path, capsys):  # noqa: F811
    where = repo.path.parent.as_posix()
    (tmp_path / "policy.json").write_bytes(json.dumps(POLICY).encode("utf-8"))
    run = repo.put_run(probe_run(tmp_path)).run_id

    # 1. the run's sandbox policy digest, and a mismatch
    code, rec = _tine(capsys, "containment", "record", run, "--policy", "policy.json",
                      "--key", "runner.key", "--repo", where, "--json")  # fmt: skip
    assert code == 0 and rec["policy_digest"] == _containment.digest(POLICY)
    code, ok = _tine(capsys, "containment", "check", run, "--policy", "policy.json",
                     "--repo", where, "--json")  # fmt: skip
    assert code == 0 and ok["ok"] and ok["policies"][0]["verification"] == "verified"
    other = _containment.digest({**POLICY, "privileges": ["CAP_SYS_ADMIN"]})
    code, bad = _tine(capsys, "containment", "check", run, "--digest", other, "--repo", where,
                      "--json")  # fmt: skip
    assert code == 1 and {f["code"] for f in bad["findings"]} == {"fail:sandbox-policy-mismatch"}

    # 2. copy self, fetch weights, spawn: flagged, held, queued, queryable
    code, scan = _tine(capsys, "containment", "scan", run, "--key", "runner.key", "--repo",
                       where, "--json")  # fmt: skip
    assert code == 0  # advisory (D12)
    categories = {f["category"] for f in scan["findings"]}
    assert {"self-replication", "egress", "unmonitored-process"} <= categories
    held = _containment_detect.recorded(repo, run)
    assert len(held) == len(scan["recorded"]) and all(r["signed"] for r in held)
    queued = {s["item"] for s in _oversight_queue._sources(repo) if s["source"] == "containment"}
    assert queued == {f"containment:{r['oid']}" for r in held}
    routes = {"routes": [{"source": "containment", "tier": "high", "label": "*"}]}
    assert _oversight_policy.route(routes, {"source": "containment"}) == ["high"]
    rows = _query(capsys, where, "SELECT oid, category FROM containment_findings")
    assert {r["oid"] for r in rows["rows"]} == {r["oid"] for r in held}
    assert rows["verification"]["counts"]["verified"] == len(held)
    rows = _query(capsys, where, "SELECT oid, policy_digest FROM sandbox_policies")
    assert [r["policy_digest"] for r in rows["rows"]] == [_containment.digest(POLICY)]

    # 3. over budget: denied on the next action; a self-signed raise is refused and routed
    _apply(repo, _policy("policy", tokens=25))
    args = SimpleNamespace(repo=where, subject=SUBJECT, key="runner.key", agent="generic")
    decisions = []
    for step in range(5):
        out = io.BytesIO()
        _budget_gate.run(args, io.BytesIO(b"{}"), out, now=lambda: T0 + step)
        decisions.append(json.loads(out.getvalue())["decision"])
        if decisions[-1] != "allow":
            break
        _spend(repo, _run(f"s{step}", 10, 0.01), at=T0 + step)
    assert decisions == ["allow", "allow", "allow", "deny"]  # 30 >= 25 after step 3
    _spend(repo, _run("s2", 10, 0.01), at=T0 + 9)  # recorded twice: counts once
    assert _budget_status.status(repo, SUBJECT, now_ms=T0)["totals"]["tokens"] == 30
    raised = _apply(repo, _policy("optimizer", serial=2, tokens=10**9), at=T0 + 10)
    body = _budget_status.check(repo, SUBJECT, now_ms=T0 + 11, key=_key("runner"))
    assert body["policy"]["limits"]["tokens"] == 25 and body["decision"] == "deny"
    (flag,) = body["flags"]
    assert {"item": f"budget:{flag}", "source": "budget"} in _oversight_queue._sources(repo)
    rows = _query(capsys, where, "SELECT oid, entry, code FROM budget_ledger")
    by_oid = {r["oid"]: r for r in rows["rows"]}
    assert by_oid[raised]["entry"] == "policy"
    assert by_oid[flag]["entry"] == "flag"
    assert by_oid[flag]["code"] == "budget.policy-optimizer-key"
    assert sum(r["entry"] == "spend" for r in rows["rows"]) == 4
    assert rows["verification"]["counts"]["failed"] == 0


def test_a_policy_record_that_disagrees_is_routed_to_oversight(repo, tmp_path):  # noqa: F811
    run = repo.put_run(probe_run(tmp_path)).run_id
    first = _containment.record(repo, run, POLICY, _key("runner"), now=0)
    wider = {**POLICY, "network_allowlist": ["*.net"]}
    second = _containment.record(repo, run, wider, _key("optimizer"), now=1)
    items = {s["item"] for s in _oversight_queue._sources(repo) if s["source"] == "containment"}
    assert items == {f"containment:{first}", f"containment:{second}"}
    assert _containment.allowlist(repo, run) == []  # the intersection: nothing widened
