"""0.83: signed collusion-testing protocols, the runner CLI and its eval verdicts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _collusion_verdicts, cli
from opentine._eval_verdict import EvalVerdictError
from opentine._schemas import validate_output
from opentine.repository import Repo
from tests.collusion_fixture import COLLUDING, HONEST, PROTOCOL, SECRET, rows
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

POLICY = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
OPTIMIZER = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
SCORER = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)


def _pub(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


@pytest.fixture
def room(tmp_path, monkeypatch):
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    Repo.init(tmp_path / "r")
    for name, key in (("policy.key", POLICY), ("opt.key", OPTIMIZER), ("scorer.key", SCORER)):
        (tmp_path / name).write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    (tmp_path / "secret").write_bytes(SECRET)
    (tmp_path / "wrong").write_bytes(SECRET + b"!")
    for name, spec in (("colluding.json", COLLUDING), ("honest.json", HONEST)):
        (tmp_path / name).write_bytes(json.dumps(spec).encode("utf-8"))
    lines = "".join(json.dumps(r) + "\n" for r in rows(n=200))
    (tmp_path / "runs.jsonl").write_bytes(lines.encode("utf-8"))
    return tmp_path


def _pin(tmp: Path) -> None:
    store = Repo.open(tmp / "r").path
    roles = (f'version = 1\n[roles]\npolicy = ["{_pub(POLICY)}"]\n'
             f'optimizer = ["{_pub(OPTIMIZER)}"]\nverdict = ["{_pub(SCORER)}"]\n')  # fmt: skip
    (store / "key-roles.toml").write_bytes(roles.encode("ascii"))
    pin_roles(store)


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main([*argv, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    row = json.loads(out) if out.strip() else {}
    if "error" not in row:
        assert validate_output(row) == [], row
    return code, row


def _sign(capsys, tmp: Path, key: str = "policy.key", **fields) -> tuple[int, dict]:
    (tmp / "spec.json").write_bytes(json.dumps({**PROTOCOL, "trials": 20, **fields}).encode())
    return _tine(capsys, "monitor", "protocol-sign", "--spec", str(tmp / "spec.json"),
                 "--secret", str(tmp / "secret"), "--key", str(tmp / key),
                 "--out", str(tmp / "protocol.json"))  # fmt: skip


def _run(capsys, tmp: Path, monitor: str = "colluding.json", *extra: str) -> tuple[int, dict]:
    return _tine(capsys, "monitor", "protocol-run", str(tmp / monitor), "--protocol",
                 str(tmp / "protocol.json"), "--runs", str(tmp / "runs.jsonl"), "--repo",
                 str(tmp / "r"), *extra)  # fmt: skip


def _secret(tmp: Path, name: str = "secret") -> tuple[str, str]:
    return "--secret", str(tmp / name)


def test_a_colluding_monitor_is_flagged_and_signed_verdicts_bind_the_claims(room, capsys):
    _pin(room)
    assert _sign(capsys, room)[0] == 0
    code, row = _run(capsys, room, "colluding.json", *_secret(room), "--key",
                     str(room / "scorer.key"), "--verdicts", str(room / "v.jsonl"))  # fmt: skip
    assert code == 0 and row["advisory_only"] and row["ok"] and not row["cleared"]
    assert row["collusion"]["flagged"] == 20 and len(row["verdicts"]) == 6
    lines = (room / "v.jsonl").read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 7
    signed = [json.loads(line) for line in lines[:-1]]
    for item in signed:
        good = _collusion_verdicts.check(item)
        assert good["run"] == "colluding-stub"
        assert item["claim"]["protocol"] == row["protocol"]
    overall = signed[0]["verdict"]
    assert overall["item"] == "collusion" and overall["score"] == "0" and not overall["passed"]
    forged = {**signed[0], "claim": {**signed[0]["claim"], "flagged": 0}}
    with pytest.raises(EvalVerdictError):
        _collusion_verdicts.check(forged)


def test_an_honest_monitor_clears(room, capsys):
    _pin(room)
    _sign(capsys, room, required=True)
    code, row = _run(capsys, room, "honest.json", *_secret(room))
    assert code == 0 and row["cleared"] and row["collusion"]["flagged"] == 0
    assert row["collusion"]["clopper_pearson"][0] == "0.000000"


def test_a_required_protocol_blocks_a_colluding_monitor(room, capsys):
    _pin(room)
    _sign(capsys, room, required=True)
    code, row = _run(capsys, room, "colluding.json", *_secret(room))
    assert code == 1 and row["ok"] is False and row["advisory_only"] is False


@pytest.mark.parametrize(("case", "code"), [
    ("unpinned", "collusion.unpinned"), ("optimizer", "collusion.optimizer-key"),
    ("scorer", "collusion.not-policy-key"), ("seed", "collusion.seed-mismatch"),
    ("tampered", "collusion.bad-signature"), ("verdict-key", "collusion.optimizer-key"),
])  # fmt: skip
def test_refusals_fail_closed(room, capsys, case, code):
    if case != "unpinned":
        _pin(room)
    key = {"optimizer": "opt.key", "scorer": "scorer.key"}.get(case, "policy.key")
    if case == "optimizer":
        # An optimizer key that is also named a policy key is still refused.
        store = Repo.open(room / "r").path
        roles = (f'version = 1\n[roles]\npolicy = ["{_pub(OPTIMIZER)}"]\n'
                 f'optimizer = ["{_pub(OPTIMIZER)}"]\n')  # fmt: skip
        (store / "key-roles.toml").write_bytes(roles.encode("ascii"))
        pin_roles(store)
    assert _sign(capsys, room, key)[0] == 0
    if case == "tampered":
        doc = json.loads((room / "protocol.json").read_bytes())
        doc["trials"] = 1
        (room / "protocol.json").write_bytes(json.dumps(doc).encode("utf-8"))
    extra = ["--key", str(room / "opt.key")] if case == "verdict-key" else []
    status, row = _run(capsys, room, "colluding.json",
                       *_secret(room, "wrong" if case == "seed" else "secret"), *extra)  # fmt: skip
    assert status != 0 and code in row["error"]["message"]


def test_a_short_secret_is_refused(room, capsys):
    (room / "secret").write_bytes(b"short")
    code, row = _sign(capsys, room)
    assert code != 0 and "collusion.weak-seed" in row["error"]["message"]
