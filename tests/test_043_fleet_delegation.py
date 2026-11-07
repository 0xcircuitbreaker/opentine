"""0.43: the ``opentine-fleet/1`` record and X32 ``opentine-delegation/1`` chains."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _fleet_record
from opentine._delegation import DelegationError, issue
from opentine._delegation_verify import verify_chain
from opentine._intoto_fleet import verify_envelope
from opentine._signing_pins import key_fingerprint
from opentine.graph import Run, RunStatus, StepKind
from opentine.harnesses._identity_meta import harness_metadata
from opentine.signing import generate_ed25519

START, END = "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"
AT = "2026-06-01T00:00:00Z"
ENV = {
    "OPENTINE_FLEET_ID": "f1",
    "OPENTINE_FLEET_MEMBER": "coder-0",
    "OPENTINE_FLEET_ROLE": "worker",
    "OPENTINE_FLEET_PARENT": "boss",
}


def _pair() -> tuple[str, bytes]:
    seed, public = generate_ed25519()
    return seed, bytes.fromhex(public)


def _chain(**leaf):
    (root, _), (mid, mid_pub), (agent, agent_pub) = _pair(), _pair(), _pair()
    first = issue(root, mid_pub, agents=["*"], actions=["*"], max_depth=1,
                  not_before=START, not_after=END)  # fmt: skip
    kwargs = {"agents": ["coder-0"], "actions": ["Bash"], "not_before": START, "not_after": END}
    second = issue(mid, agent_pub, parent=first, **{**kwargs, **leaf})
    return [first, second], agent, key_fingerprint(agent_pub)


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT", "OPENTINE_DELEGATION", *ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _code(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def test_capture_reads_fleet_env_and_delegation_file(room, monkeypatch):
    chain, _, _ = _chain()
    (room / "chain.json").write_text(json.dumps(chain), encoding="utf-8")
    for name, value in {**ENV, "OPENTINE_DELEGATION": str(room / "chain.json")}.items():
        monkeypatch.setenv(name, value)

    class Harness:
        name, model_info = "claude-code", "m"

    meta = harness_metadata(Harness(), {})
    assert meta["fleet"] == {"scheme": "opentine-fleet/1", "fleet_id": "f1", "member": "coder-0",
                             "role": "worker", "parent": "boss"}  # fmt: skip
    assert meta["delegation"] == chain
    monkeypatch.setenv("OPENTINE_FLEET_ID", "bad id!")
    assert "fleet" not in harness_metadata(Harness(), {})  # malformed: dropped, never guessed


def test_chain_verifies_and_each_refusal_has_its_code():
    chain, _, signer = _chain()
    ok = verify_chain(chain, signer=signer, at=AT, agent="coder-0", actions=["Bash"])
    assert ok["root"] == chain[0]["issuer"] and len(ok["links"]) == 2
    cases = {
        "delegation.expired": dict(at="2028-01-01T00:00:00Z"),
        "delegation.scope-violation": dict(actions=["Write"]),
        "delegation.wrong-signer": dict(signer=chain[1]["issuer"]),
    }
    for code, override in cases.items():
        with pytest.raises(DelegationError) as caught:
            verify_chain(chain, **{"signer": signer, "at": AT, **override})
        assert caught.value.code == code
    with pytest.raises(DelegationError) as caught:
        verify_chain(chain[1:], signer=signer, at=AT)
    assert caught.value.code == "delegation.broken-chain"
    forged = [chain[0], {**chain[1], "scope": {**chain[1]["scope"], "actions": ["*"]}}]
    with pytest.raises(DelegationError) as caught:
        verify_chain(forged, signer=signer, at=AT)
    assert caught.value.code == "delegation.bad-signature"
    wide, _, wide_signer = _chain(not_after="2030-01-01T00:00:00Z")
    with pytest.raises(DelegationError) as caught:
        verify_chain(wide, signer=wide_signer, at=AT)
    assert caught.value.code == "delegation.scope-violation"
    with pytest.raises(DelegationError) as caught:
        verify_chain(chain, signer=signer, at=AT, root=chain[1]["issuer"])
    assert caught.value.code == "delegation.broken-chain"


def test_depth_limit():
    (root, _), (mid, mid_pub), (_, leaf_pub) = _pair(), _pair(), _pair()
    first = issue(root, mid_pub, agents=["*"], actions=["*"], not_before=START, not_after=END)
    second = issue(mid, leaf_pub, agents=["*"], actions=["*"], parent=first,
                   not_before=START, not_after=END)  # fmt: skip
    with pytest.raises(DelegationError) as caught:
        verify_chain([first, second], signer=key_fingerprint(leaf_pub), at=AT)
    assert caught.value.code == "delegation.too-deep"


def _signed_run(room: Path, chain, agent_seed: str) -> Path:
    metadata = {"harness": "claude-code", "fleet": _fleet_record.from_env(ENV),
                "delegation": chain}  # fmt: skip
    run = Run(run_id="r1", model_info="m", metadata=metadata)
    run.add_step(StepKind.tool, {"name": "Bash", "arguments": {"command": "ls"}})
    run.status = RunStatus.completed
    path = room / "r1.tine"
    run.save(path, sign_key=agent_seed, sign_algorithm="ed25519", signed_at=AT)
    return path


def _delegation(capsys, *argv: str) -> tuple[int, dict]:
    code = _code("verify", *argv, "--offline", "--json")
    report = json.loads(capsys.readouterr().out)
    return code, next(c for c in report["checks"] if c["name"] == "delegation")


def test_verify_offline_reports_the_chain(room, capsys):
    chain, seed, _ = _chain()
    path = _signed_run(room, chain, seed)
    code, check = _delegation(capsys, str(path), "--trust-embedded-key")
    assert check["outcome"] == "pass" and chain[0]["issuer"] in check["detail"]
    assert check["trust_basis"].startswith("unpinned root")
    other, other_seed, _ = _chain(actions=["Write"])
    path = _signed_run(room, other, other_seed)
    code, check = _delegation(capsys, str(path), "--trust-embedded-key")
    assert code != 0 and check["reason"] == "delegation.scope-violation"


def test_fleet_record_sign_attest_and_verify(room, capsys):
    chain, seed, _ = _chain()
    path = _signed_run(room, chain, seed)
    key_seed, public = generate_ed25519()
    (room / "k.key").write_text(key_seed + "\n", encoding="utf-8")
    (room / "k.pub").write_text(public + "\n", encoding="utf-8")
    argv = ("fleet", "record", str(path), "--sign-key", "k.key", "--out", "rec.json",
            "--attest", "fleet.intoto.jsonl", "--attest-key", "k.key", "--json")  # fmt: skip
    assert _code(*argv) == 0
    row = json.loads(capsys.readouterr().out)
    assert row["record"]["fleet_id"] == "f1" and row["delegation"] == 2
    statement = verify_envelope(json.loads((room / "fleet.intoto.jsonl").read_text()), public)
    assert statement["predicate"]["delegation"] == [_digest(c) for c in chain]
    assert _code("fleet", "record", "rec.json", "--pubkey", "k.pub") == 0
    document = json.loads((room / "rec.json").read_text())
    document["run_id"] = "elsewhere"
    (room / "moved.json").write_text(json.dumps(document), encoding="utf-8")
    assert _code("fleet", "record", "moved.json", "--pubkey", "k.pub") == 4


def _digest(cert) -> str:
    from opentine._delegation import digest

    return digest(cert)


def test_key_delegate_cli_round_trip(room, capsys):
    for name in ("p", "a"):
        seed, public = generate_ed25519()
        (room / f"{name}.key").write_text(seed + "\n", encoding="utf-8")
        (room / f"{name}.pub").write_text(public + "\n", encoding="utf-8")
    assert _code("key", "delegate", "p.key", "--to", "a.pub", "--agent", "*", "--action",
                 "Bash", "--out", "c.json") == 0  # fmt: skip
    assert _code("key", "delegation", "show", "c.json", "--json") == 0
    assert _code("key", "delegation", "verify", "c.json", "--signer", "a.pub") == 0
    assert _code("key", "delegation", "verify", "c.json", "--signer", "p.pub") == 4
    assert _code("key", "delegation", "verify", "c.json", "--signer", "a.pub",
                 "--action", "Write") == 4  # fmt: skip
    capsys.readouterr()
