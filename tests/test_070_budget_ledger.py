"""0.70 (release 0.69.0): budget policies, the signed spend ledger and the next-action gate."""

from __future__ import annotations

import io
import json
import math
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _budget_gate, _budget_ledger, _budget_policy, _budget_status, _schemas, cli
from opentine._signing_pins import key_fingerprint
from opentine.core import Run, RunStatus, StepKind
from opentine.repository import Repo
from opentine.repository._holds import BUDGET_LEDGER, HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"runner": 11, "policy": 12, "optimizer": 13, "stranger": 14}
SUBJECT = "loop:opt"
T0 = 1_800_000_000_000  # a fixed clock, in ms


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    body = json.loads(out) if out.strip().startswith("{") else {}
    if body and "error" not in body:
        assert _schemas.validate_output(body) == [], body
    return code, body


def _run(name: str, tokens: int, cost: float) -> Run:
    run = Run(id=name, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.model, {"text": "a"}, {"text": "b"}, cost=cost,
                 usage={"input": tokens - 2, "output": 2})  # fmt: skip
    run.status = RunStatus.completed
    return run


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    repo = Repo.init(tmp_path / "r")
    for name in SEEDS:
        (tmp_path / f"{name}.key").write_bytes(bytes([SEEDS[name]]).hex().encode() * 32)
    roles = {"runner": [_fpr("runner")], "policy": [_fpr("policy")],
             "optimizer": [_fpr("optimizer")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    return repo


def _policy(signer: str, *, serial: int = 1, on_limit: str = "deny", **limits) -> dict:
    doc = _budget_policy.build(SUBJECT, limits, serial=serial, on_limit=on_limit,
                               issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    return _budget_policy.sign(doc, _key(signer))


def _apply(repo, doc: dict, at: int = T0) -> str:
    return _budget_ledger.append(repo, SUBJECT, "policy", {"policy": doc}, _key("runner"), at_ms=at)


def _spend(repo, run: Run, at: int = T0) -> str:
    from opentine._cost_export import aggregate

    fields = {"run": run.id, "cost": aggregate(run), "gpu_hours": 0.0, "egress_bytes": 0}
    return _budget_ledger.append(repo, SUBJECT, "spend", fields, _key("runner"), at_ms=at)


def test_ledger_total_equals_the_cost_export(repo, tmp_path, capsys):
    costs = [0.1, 0.2, 0.30000000000000004, 1e-9]
    names = []
    for i, cost in enumerate(costs):
        _run(f"r{i}", 10 + i, cost).save(tmp_path / f"r{i}.tine")
        names.append(f"r{i}.tine")
    code, body = _tine(capsys, "budget", "record", SUBJECT, *names, "--key", "runner.key",
                       "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and len(body["entries"]) == 4
    exported, tokens = [], 0
    for name in names:
        assert _tine(capsys, "cost", name, "--statement", "s.json", "--sign-key",
                     "runner.key")[0] == 0  # fmt: skip
        agg = json.loads((tmp_path / "s.json").read_bytes())["aggregate"]
        exported.append(agg["total_cost"])
        tokens += agg["total_tokens"]
    code, ledger = _tine(capsys, "budget", "ledger", SUBJECT, "--repo", "r", "--json")
    assert code == 0
    assert ledger["totals"]["money_usd"] == math.fsum(exported)
    assert ledger["totals"]["tokens"] == tokens and ledger["totals"]["runs"] == 4
    ids = [row["id"] for row in ledger["entries"]]
    assert [row["previous"] for row in ledger["entries"]] == [None, *ids[:-1]]  # hash chain


def test_over_budget_denies_the_next_action_within_one_step(repo):
    _apply(repo, _policy("policy", tokens=25))
    args = SimpleNamespace(repo=repo.path.parent.as_posix(), subject=SUBJECT,
                           key="runner.key", agent="generic")  # fmt: skip
    decisions, crossed = [], None
    for step in range(5):
        out = io.BytesIO()
        _budget_gate.run(args, io.BytesIO(b"{}"), out, now=lambda: T0 + step)
        decisions.append(json.loads(out.getvalue())["decision"])
        if decisions[-1] != "allow":
            break
        _spend(repo, _run(f"s{step}", 10, 0.01), at=T0 + step)  # the step runs, then is recorded
        if crossed is None and _budget_status.status(repo, SUBJECT, now_ms=T0)["over"]:
            crossed = step
    assert crossed == 2  # 30 tokens >= 25 after the third step
    assert decisions == ["allow", "allow", "allow", "deny"]  # the very next action
    assert len(decisions) - 1 - crossed == 1


def test_hook_and_mcp_dialects_refuse_at_the_limit(repo):
    _apply(repo, _policy("policy", money_usd=0.05))
    _spend(repo, _run("big", 10, 0.06))
    body = _budget_gate.respond("claude-code", _budget_gate.decide(repo, SUBJECT, None, T0))
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _budget_gate.respond("gemini", {"decision": "allow", "reason": "", "over": []}) == {}
    guard = _budget_gate.BudgetMcpGuard(repo, SUBJECT, _key("runner"), now=lambda: T0)
    other = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
    assert guard.check(other) == (other, None, None)
    call = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}\n'
    forward, back, held = guard.check(call)
    assert forward is None and held == call
    reply = json.loads(back)
    assert reply["id"] == 2 and reply["error"]["code"] == _budget_gate.ERROR_CODE
    assert reply["error"]["data"]["opentine.budget"]["over"] == ["money_usd"]


@pytest.mark.parametrize(
    ("signer", "serial", "limit", "tamper", "code"),
    [
        ("optimizer", 2, 500, False, "fail:budget.policy-optimizer-key"),
        ("stranger", 2, 500, False, "fail:budget.limit-raise"),
        ("policy", 1, 500, False, "fail:budget.policy-rollback"),
        ("policy", 2, 500, True, "fail:budget.policy-unsigned"),
    ],
)
def test_an_agent_raising_its_own_limit_is_refused_and_routed(repo, signer, serial, limit,
                                                              tamper, code):  # fmt: skip
    from opentine import _oversight, _oversight_policy, _oversight_queue

    _apply(repo, _policy("policy", tokens=100))
    raised = _policy(signer, serial=serial, tokens=limit)
    if tamper:  # edited after signing
        raised["limits"]["tokens"] = 10**9
    bad = _apply(repo, raised, at=T0 + 1)
    body = _budget_status.check(repo, SUBJECT, now_ms=T0 + 2, key=_key("runner"))
    assert body["policy"]["limits"]["tokens"] == 100  # the policy in force stays
    assert [f["code"] for f in body["findings"] if f["entry"] == bad] == [code]
    (flag,) = body["flags"]
    again = _budget_status.check(repo, SUBJECT, now_ms=T0 + 3, key=_key("runner"))
    assert again["flags"] == []  # flagged once
    sources = _oversight_queue._sources(repo)
    assert {"item": f"budget:{flag}", "source": "budget"} in sources
    assert _oversight.parse_item(f"budget:{flag}")["source"] == "budget"
    policy = {"routes": [{"source": "budget", "tier": "high", "label": "*"}]}
    assert _oversight_policy.route(policy, {"source": "budget"}) == ["high"]
    with pytest.raises(HoldError):
        release(repo, BUDGET_LEDGER + SUBJECT)


def test_lowering_needs_no_role_and_a_pinned_policy_key_may_raise(repo):
    _apply(repo, _policy("policy", tokens=100))
    _apply(repo, _policy("stranger", serial=2, tokens=50), at=T0 + 1)
    assert _budget_status.status(repo, SUBJECT, now_ms=T0)["policy"]["limits"]["tokens"] == 50
    _apply(repo, _policy("policy", serial=3, tokens=400), at=T0 + 2)
    body = _budget_status.status(repo, SUBJECT, now_ms=T0)
    assert body["policy"]["limits"]["tokens"] == 400 and body["policy"]["signer"] == _fpr("policy")
    assert not [f for f in body["findings"] if f["level"] == "fail"]


def test_wall_clock_uses_the_injected_clock_and_escalation_is_flagged_once(repo):
    _apply(repo, _policy("policy", on_limit="escalate", wall_clock_s=60))
    assert _budget_status.status(repo, SUBJECT, now_ms=T0 + 59_999)["decision"] == "allow"
    first = _budget_status.check(repo, SUBJECT, now_ms=T0 + 60_000, key=_key("runner"))
    assert first["decision"] == "escalate" and first["over"] == ["wall_clock_s"]
    assert len(first["flags"]) == 1
    later = _budget_status.check(repo, SUBJECT, now_ms=T0 + 61_000, key=_key("runner"))
    assert later["flags"] == []


def test_cli_status_check_and_apply_report_with_schemas(repo, tmp_path, capsys):
    code, signed = _tine(capsys, "budget", "sign-policy", SUBJECT, "--serial", "1", "--tokens",
                         "5", "--key", "policy.key", "--out", "p.json",
                         "--at", "2027-01-15T08:00:00Z", "--json")  # fmt: skip
    assert code == 0 and signed["policy"]["signer"] == _fpr("policy")
    code, applied = _tine(capsys, "budget", "apply", "p.json", "--key", "runner.key", "--repo",
                          "r", "--json")  # fmt: skip
    assert code == 0 and applied["accepted"]
    assert _tine(capsys, "budget", "check", SUBJECT, "--repo", "r", "--json")[0] == 0
    _run("x", 10, 0.0).save(tmp_path / "x.tine")
    assert _tine(capsys, "budget", "record", SUBJECT, "x.tine", "--key", "runner.key",
                 "--repo", "r")[0] == 0  # fmt: skip
    code, checked = _tine(capsys, "budget", "check", SUBJECT, "--repo", "r", "--json")
    assert code == 1 and checked["status"]["decision"] == "deny"
    code, status = _tine(capsys, "budget", "status", SUBJECT, "--repo", "r", "--json")
    assert code == 0 and status["status"]["over"] == ["tokens"]
    assert status["status"]["roles"] == "pinned"
