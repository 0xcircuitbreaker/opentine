"""0.57: what a self-improving loop cannot route around at ``tine promote``.

A ``policy`` key role pins the promotion policy to a signed attestation; an
approval is bound to the holder it replaces and the label's sequence; a first
promotion and a canary check the baseline's run and signer; a candidate run
names its loop. Each refusal is a ``promote.*`` code.
"""

from __future__ import annotations

import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine.coord import _loop_stop, _tasks
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import PROMOTER, RUN_A, RUN_B, fingerprint, policy, write_key
from tests.test_058_promote import Room, _codes, _good, _tine

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
SIGNER = "9e" * 32


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    return Room(tmp_path)


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _roles(repo: Repo, **roles: list[str]) -> None:
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    pin_roles(repo.path)  # 0.59: roles grant only from an owner-signed trust bundle


def _at(repo: Repo) -> list[str]:
    return ["--repo", repo.path.parent.as_posix()]


def _sign_policy(room: Room, capsys, seed: str, name: str) -> str:
    out = room.base / name
    code, row = _tine(capsys, "promote", policy(room.base).as_posix(), "--sign-policy", "--key",
                      write_key(room.base / f"{name}.key", seed).as_posix(), "--out",
                      out.as_posix(), "--json")  # fmt: skip
    assert code == 0 and row["action"] == "sign-policy"
    return out.as_posix()


def test_a_policy_role_requires_a_signed_policy_from_another_key(room, repo, capsys):
    _roles(repo, policy=[fingerprint(SIGNER), fingerprint(PROMOTER)])
    args = [*_good(room, capsys), *_at(repo)]
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and "promote.policy-unsigned" in _codes(row)
    own = _sign_policy(room, capsys, PROMOTER, "own.json")  # the promoting key: never counts
    code, row = room.promote(capsys, RUN_B, *args, "--policy-attestation", own)
    assert code == 1 and "promote.policy-unsigned" in _codes(row)
    _roles(repo, policy=[fingerprint(SIGNER)])
    signed = _sign_policy(room, capsys, SIGNER, "signed.json")
    edited = policy(room.base, budget_usd="1000")  # the loop raises its own cap
    code, row = room.promote(capsys, RUN_B, *args, "--policy-attestation", signed, pol=edited)
    assert code == 1 and _codes(row) == {"promote.policy-unsigned"}
    code, row = room.promote(capsys, RUN_B, *args, "--policy-attestation", signed)
    assert code == 0, row.get("refusals")
    assert any(i["uri"] == f"policy:{fingerprint(SIGNER)}" for i in row["inputs"])
    decision = json.loads((room.base / "out" / "decision.json").read_text("utf-8"))
    assert decision["claim"]["policy_attestation"]["signer"] == fingerprint(SIGNER)


def test_an_approval_does_not_survive_a_revert(room, capsys):
    args = _good(room, capsys)
    at = args.index("--approval")
    first = room.base / "first-approval.json"
    shutil.copy(args[at + 1], first)
    assert room.promote(capsys, RUN_B, *args, out="one")[0] == 0
    assert room.promote(capsys, RUN_B, "--revert", out="two")[0] == 0
    args[at + 1] = first.as_posix()
    code, row = room.promote(capsys, RUN_B, *args, out="three")
    assert code == 1 and _codes(row) == {"promote.approval-stale"}
    approval = json.loads(first.read_text("utf-8"))["claim"]
    assert (approval["previous"], approval["sequence"]) == (None, 0)


def test_a_first_promotion_baseline_must_score_another_run(room, capsys):
    args = _good(room, capsys)
    at = args.index("--baseline-evals")
    args[at + 1] = room.evals("self", RUN_B, lambda i: i % 2 == 0).as_posix()
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and "promote.evals-not-baseline" in _codes(row)


def test_the_canary_checks_the_baseline_run_and_signer(room, capsys):
    assert room.promote(capsys, RUN_B, *_good(room, capsys), out="one")[0] == 0
    fine = room.evals("canary-ok", RUN_B, lambda i: i % 2 == 0)
    cases = (("cb-self", RUN_B, None, "promote.evals-not-baseline"),
             ("cb-rogue", RUN_A, "8d" * 32, "promote.untrusted-eval"))  # fmt: skip
    for name, run, signer, code_ in cases:
        extra = {"signer": signer} if signer else {}
        base = room.evals(name, run, lambda i: i % 10 == 0, **extra)
        code, row = room.promote(capsys, RUN_B, "--canary", fine.as_posix(), "--baseline-evals",
                                 base.as_posix(), out=f"c-{name}")  # fmt: skip
        assert code == 1 and code_ in _codes(row)


def _loop_run(repo: Repo, **metadata: str) -> str:
    run = Run(id="gen", model_info="m", user_prompt="p", policies=PolicySet().to_dict(),
              metadata=metadata)  # fmt: skip
    run.add_step(StepKind.done, {"text": "candidate"})
    return repo.put_run(run).run_id


@pytest.mark.parametrize("via", ["loop", "task"])
def test_a_stopped_loops_candidate_is_refused_without_loop(room, repo, capsys, via):
    _tasks.add(repo, "gen-7", loop="opt")
    meta = {"opentine.loop": "opt"} if via == "loop" else {"opentine.task": "gen-7"}
    run = _loop_run(repo, **meta)
    args = [*_good(room, capsys, run), *_at(repo)]
    _loop_stop.stop(repo, "opt", Ed25519PrivateKey.from_private_bytes(b"\x07" * 32))
    code, row = room.promote(capsys, run, *args)
    assert code == 1 and _codes(row) == {"promote.loop-stopped"}
