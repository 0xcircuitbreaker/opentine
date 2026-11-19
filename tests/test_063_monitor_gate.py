"""0.63: the inline gate: verdict claims, modes, deadline, alternates, stop tokens."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _key_roles, _monitor_stop, _monitor_verdict, _schemas
from opentine._key_roles import normalize_key
from opentine._monitor_gate import Gate
from opentine._monitors import MonitorError, parse
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

KEY = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
RULES = [{"tool": "shell*", "pattern": "rm -rf", "score": 0.9},
         {"tool": "*", "pattern": "curl", "score": 0.6, "action": "defer"}]  # fmt: skip


def config(**over):
    doc = {"version": 1, "mode": over.pop("mode", "gate"), "deadline_ms": 100,
           "fail_closed": over.pop("fail_closed", False),
           "monitor": {"id": "rules", "kind": "rule", "threshold": 0.5, "action": "block",
                       "rules": RULES}}  # fmt: skip
    doc.update(over)
    return parse(doc)


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def call(cmd: str) -> dict:
    return {"name": "shell", "arguments": {"cmd": cmd}}


def test_the_config_is_checked():
    with pytest.raises(MonitorError):
        parse({"version": 1, "monitor": {"id": "x", "kind": "nope"}})
    with pytest.raises(MonitorError):
        config(deadline_ms=0)
    with pytest.raises(MonitorError):
        config(mode="sometimes")


def test_gate_mode_needs_a_repository_and_a_key(repo):
    with pytest.raises(MonitorError):
        Gate(config(), repo=repo)
    Gate(config(mode="advisory"))  # advisory may run without one


def test_advisory_never_blocks_and_holds_the_flagged_verdict(repo):
    gate = Gate(config(mode="advisory"), repo=repo, key=KEY)
    decision = gate.decide("tools/call", call("rm -rf /"))
    assert decision["outcome"] == "forward"
    claim = decision["claim"]
    assert claim["action"] == "block" and claim["enforced"] is False
    assert _schemas.validate(claim, "opentine-monitor-verdict-1")[1] == []
    assert _monitor_verdict.held(repo) == [decision["verdict"]]
    assert gate.decide("tools/call", call("ls"))["verdict"] is None  # allow: not recorded


def test_gate_mode_blocks_and_the_verdict_verifies_with_a_pinned_monitor_key(repo):
    gate = Gate(config(), repo=repo, key=KEY)
    decision = gate.decide("tools/call", call("rm -rf /"))
    assert decision["outcome"] == "block" and decision["claim"]["enforced"] is True
    oid = decision["verdict"]
    row = _monitor_verdict.verify(repo, oid)
    assert row["signed"] and row["problems"] == []
    assert row["verification"].startswith("unverified: the monitor role is unpinned")
    pub = KEY.public_key().public_bytes_raw().hex()
    (repo.path / "key-roles.toml").write_text(f'version = 1\n[roles]\nmonitor = ["{pub}"]\n')
    pin_roles(repo.path)
    assert _monitor_verdict.verify(repo, oid)["verification"] == "verified"
    with pytest.raises(HoldError):
        release(repo, oid)


def test_the_monitor_role_is_guarded_against_the_optimizer_key():
    key = normalize_key("ab" * 32)
    found = _key_roles.lint({"optimizer": [key], "monitor": [key]})
    assert any(f["code"] == "fail:key-separation.shared" and f["role"] == "monitor"
               for f in found)  # fmt: skip


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Slow:
    identity = {"id": "slow", "kind": "command", "model_digest": None}

    def __init__(self, clock, seconds, score=0.0):
        self.clock, self.seconds, self.value = clock, seconds, score

    def score(self, request):
        self.clock.now += self.seconds  # the injected clock moves; no real waiting
        return {"score": self.value}


@pytest.mark.parametrize("fail_closed, outcome", [(True, "block"), (False, "forward")])
def test_a_missed_deadline_follows_the_operators_fail_mode(repo, fail_closed, outcome):
    clock = Clock()
    cfg = config(fail_closed=fail_closed)
    cfg["monitor"] = Slow(clock, 0.5)  # 500 ms against a 100 ms deadline
    decision = Gate(cfg, repo=repo, key=KEY, clock=clock).decide("tools/call", call("ls"))
    assert decision["outcome"] == outcome
    assert decision["claim"]["decided_by"] == "deadline"
    assert decision["claim"]["latency_ms"] == 500
    assert (decision["verdict"] is not None) == fail_closed


def test_a_monitor_still_running_at_the_deadline_is_a_miss(repo):
    gate = Gate(config(fail_closed=True), repo=repo, key=KEY,
                runner=lambda fn, seconds: (False, None, None))  # fmt: skip
    decision = gate.decide("tools/call", call("ls"))
    assert decision["outcome"] == "block" and decision["claim"]["decided_by"] == "deadline"


def test_a_monitor_error_is_recorded_as_such(repo):
    gate = Gate(config(fail_closed=True), repo=repo, key=KEY,
                runner=lambda fn, seconds: (True, None, RuntimeError("down")))  # fmt: skip
    assert gate.decide("tools/call", call("ls"))["claim"]["decided_by"] == "error"


def test_resample_records_both_trajectories(repo):
    cfg = config()
    cfg["action"] = "resample"
    cfg["monitor"].__init__("rules", [{"tool": "*", "pattern": "rm", "score": 0.9}])
    calm = Gate(cfg, repo=repo, key=KEY, alternate=lambda role, req: call("ls"))
    decision = calm.decide("tools/call", call("rm x"))
    claim = decision["claim"]
    assert decision["outcome"] == "replace" and claim["chosen"] == "resample"
    assert [t["role"] for t in claim["trajectories"]] == ["original", "resample"]
    assert claim["trajectories"][1]["score"] == 0.0
    meta = decision["replacement"]["_meta"][_monitor_verdict.META_KEY]
    assert meta["verdict"] == decision["verdict"]
    still = Gate(cfg, repo=repo, key=KEY, alternate=lambda role, req: call("rm y"))
    again = still.decide("tools/call", call("rm x"))
    assert again["outcome"] == "block" and again["claim"]["chosen"] == "none"


def test_defer_takes_the_trusted_action_and_no_alternate_blocks(repo):
    trusted = Gate(config(), repo=repo, key=KEY, alternate=lambda role, req: call("echo"))
    decision = trusted.decide("tools/call", {"name": "fetch", "arguments": {"u": "curl x"}})
    assert decision["outcome"] == "replace" and decision["claim"]["chosen"] == "trusted"
    alone = Gate(config(), repo=repo, key=KEY)
    blocked = alone.decide("tools/call", {"name": "fetch", "arguments": {"u": "curl x"}})
    assert blocked["outcome"] == "block" and blocked["claim"]["action"] == "defer"


def test_reasoning_is_captured_redacted_or_unavailable(repo):
    gate = Gate(config(mode="advisory"), repo=repo, key=KEY)
    claim = gate.decide("tools/call", call("rm -rf"), reasoning="I will clean up")["claim"]
    assert claim["reasoning"] == {
        "state": "captured",
        "digest": _monitor_verdict.text_digest("I will clean up"),
    }
    assert gate.decide("tools/call", call("rm -rf"))["claim"]["reasoning"] == {
        "state": "unavailable", "digest": None}  # fmt: skip
    redacting = Gate(config(mode="advisory", reasoning="redacted"), repo=repo, key=KEY)
    claim = redacting.decide("tools/call", call("rm -rf"), reasoning="x")["claim"]
    assert claim["reasoning"]["state"] == "redacted"


def test_a_stop_token_blocks_in_either_mode_and_is_never_released(repo):
    token = _monitor_stop.stop(repo, "agent:coder", KEY, reason="halt")
    gate = Gate(config(mode="advisory"), repo=repo, key=KEY, agent="coder")
    decision = gate.decide("tools/call", call("ls"))
    assert decision["outcome"] == "block"
    assert decision["claim"]["decided_by"] == "stop-token"
    assert decision["claim"]["stop"] == token
    other = Gate(config(mode="advisory"), repo=repo, key=KEY, agent="writer")
    assert other.decide("tools/call", call("ls"))["outcome"] == "forward"
    with pytest.raises(HoldError):
        release(repo, token)
    assert _monitor_stop.tokens(repo)[0]["verification"] == "verified"  # no stopper role named
    with pytest.raises(ValueError):
        _monitor_stop.stop(repo, "everyone", KEY)


def test_an_unreadable_holds_file_is_a_stop(repo):
    (repo.path / "holds").write_bytes(b"not json")
    gate = Gate(config(mode="advisory"), repo=repo)
    assert gate.decide("tools/call", call("ls"))["outcome"] == "block"
