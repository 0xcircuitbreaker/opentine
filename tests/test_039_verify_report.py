"""0.39.0: X20 signature-bound timestamps, X22 signed verify reports, the in-toto
``replay/v1`` predicate, and custody records on ``opentine-log/1``.

Everything runs offline: TSA tokens are minted locally by the 0.31 helpers and
every CLI call runs inside ``no_network``.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402

from opentine import (  # noqa: E402  # noqa: E402
    Run,
    RunStatus,
    StepKind,
    _custody,
    _verify_report_sign,
    cli,
)
from opentine import _timestamp_sidecar as sidecar  # noqa: E402
from opentine._intoto_replay import (  # noqa: E402
    PREDICATE_TYPE,
    validate_predicate,
    verify_envelope,
)
from opentine._offline_guard import no_network  # noqa: E402
from opentine._signing_keys import generate_ed25519  # noqa: E402
from tests.test_timestamp_offline_0_31 import _tine, pki, token  # noqa: E402


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="ts_run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path


def _keys(where: Path, name: str = "k") -> tuple[Path, Path]:
    private, public = generate_ed25519()
    (where / f"{name}.hex").write_text(private, encoding="ascii")
    (where / f"{name}.pub").write_text(public, encoding="ascii")
    return where / f"{name}.hex", where / f"{name}.pub"


def _ca(room: Path):
    ca, tsa, key = pki()
    (room / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return tsa, key


def tine(monkeypatch, *argv: str) -> int:
    with no_network():
        return _tine(monkeypatch, *argv)


def _refuse(*_a, **_k):
    raise AssertionError("custody touched the network")


def repo_tine(monkeypatch, *argv: str) -> int:
    """``no_network`` also refuses ``gethostname``, which the repository lock uses
    for its owner record; here only real network calls are refused."""
    with monkeypatch.context() as patch:
        for name in ("create_connection", "getaddrinfo", "gethostbyname"):
            patch.setattr(socket, name, _refuse)
        patch.setattr(socket.socket, "connect", _refuse)
        return _tine(monkeypatch, *argv)


def _sign_run(monkeypatch, room: Path, key: Path) -> None:
    argv = ("sign", "run.tine", "--algorithm", "ed25519", "--ed25519-key-file", str(key))
    assert tine(monkeypatch, *argv, "--save", "run.tine", "--overwrite") == 0


# --------------------------------------------------------------------------- #
# X20: a token over the signature gives the verified signing time
# --------------------------------------------------------------------------- #


def test_signature_bound_timestamp_verifies_and_sets_signing_time(room, monkeypatch, capsys):
    key, pub = _keys(room)
    _sign_run(monkeypatch, room, key)
    tsa, tsa_key = _ca(room)
    capsys.readouterr()
    assert tine(monkeypatch, "timestamp", "data", "run.tine", "--signature") == 0
    bound = capsys.readouterr().out
    assert bound.startswith(sidecar.SIG_PREFIX)
    assert bound == sidecar.signature_bounds(room / "run.tine")[0]
    (room / "t.tsr").write_bytes(token(bound.encode(), tsa, tsa_key))
    assert tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 0
    argv = ("verify", "run.tine", "--offline", "--pubkey", str(pub), "--tsa-roots", "ca.pem")
    assert tine(monkeypatch, *argv, "--report", "r.json") == 0
    report = json.loads((room / "r.json").read_text(encoding="utf-8"))
    assert report["schema"] == "tine-verify-report/2"
    (entry,) = report["timestamps"]
    assert entry["binding"] == "signature" and entry["outcome"] == "pass"
    assert report["signing_time"] == entry["gen_time"]


def test_a_token_over_a_different_signature_fails(room, monkeypatch):
    key, _ = _keys(room)
    other, _ = _keys(room, "other")
    _sign_run(monkeypatch, room, other)
    stale = sidecar.signature_bounds(room / "run.tine")[0]
    _sign_run(monkeypatch, room, key)  # the run now carries a different signature
    assert stale not in sidecar.signature_bounds(room / "run.tine")
    tsa, tsa_key = _ca(room)
    sidecar.attach(room / "run.tine", stale, token(stale.encode(), tsa, tsa_key))
    code = tine(monkeypatch, "verify", "run.tine", "--offline", "--tsa-roots", "ca.pem",
                "--report", "r.json")  # fmt: skip
    report = json.loads((room / "r.json").read_text(encoding="utf-8"))
    stamp = next(c for c in report["checks"] if c["name"] == "timestamp")
    assert code == 1 and stamp["reason"] == "timestamp.signature-mismatch"
    assert "signing_time" not in report


def test_root_bound_tokens_still_verify(room, monkeypatch, capsys):
    tsa, tsa_key = _ca(room)
    assert tine(monkeypatch, "timestamp", "data", "run.tine") == 0
    bound = capsys.readouterr().out
    assert not bound.startswith("sig:")
    (room / "t.tsr").write_bytes(token(bound.encode(), tsa, tsa_key))
    assert tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 0
    assert tine(monkeypatch, "verify", "run.tine", "--offline", "--tsa-roots", "ca.pem",
                "--report", "r.json") == 0  # fmt: skip
    report = json.loads((room / "r.json").read_text(encoding="utf-8"))
    assert report["timestamps"][0]["binding"] == "root" and "signing_time" not in report


# --------------------------------------------------------------------------- #
# X22: the verify report is signed evidence
# --------------------------------------------------------------------------- #


def _signed_report(monkeypatch, room: Path) -> tuple[Path, Path]:
    key, pub = _keys(room, "reporter")
    argv = ("verify", "run.tine", "--offline", "--report", "r.json", "--sign-key", str(key))
    assert tine(monkeypatch, *argv, "--timestamp") == 0
    return room / "r.json", pub


def test_signed_report_round_trips_with_a_timestamp(room, monkeypatch, capsys):
    path, pub = _signed_report(monkeypatch, room)
    raw = path.read_bytes()
    doc = json.loads(raw)
    assert raw == _verify_report_sign.dumps(doc)  # canonical JSON on disk
    assert doc["signature"]["scheme"] == "tine-sig/3"
    bound = (room / "r.json.tsdata").read_text(encoding="ascii")
    assert bound == _verify_report_sign.bound(doc)
    tsa, tsa_key = _ca(room)
    (room / "t.tsr").write_bytes(token(bound.encode(), tsa, tsa_key))
    assert tine(monkeypatch, "verify-report", "attach", "r.json", "t.tsr") == 0
    capsys.readouterr()
    argv = ("verify-report", "check", "r.json", "--pubkey", str(pub), "--tsa-roots", "ca.pem")
    assert tine(monkeypatch, *argv, "--json") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] and result["evidence"] and result["signing_time"]
    assert result["signature"]["trust_basis"].startswith("supplied key")


def test_tampered_report_fails(room, monkeypatch):
    path, pub = _signed_report(monkeypatch, room)
    doc = json.loads(path.read_bytes())
    doc["verdict"] = "fail" if doc["verdict"] == "pass" else "pass"
    path.write_bytes(_verify_report_sign.dumps(doc))
    assert tine(monkeypatch, "verify-report", "check", "r.json", "--pubkey", str(pub)) == 4
    _, other = _keys(room, "stranger")
    doc["verdict"] = "pass" if doc["verdict"] == "fail" else "fail"  # restore
    path.write_bytes(_verify_report_sign.dumps(doc))
    assert tine(monkeypatch, "verify-report", "check", "r.json", "--pubkey", str(pub)) == 0
    assert tine(monkeypatch, "verify-report", "check", "r.json", "--pubkey", str(other)) == 4


def test_report_v1_stays_readable_but_is_not_evidence(room, monkeypatch, capsys):
    assert tine(monkeypatch, "verify", "run.tine", "--offline", "--report", "r.json") == 0
    doc = json.loads((room / "r.json").read_text(encoding="utf-8"))
    doc["schema"] = "tine-verify-report/1"
    doc.pop("signing_time", None)
    (room / "r1.json").write_text(json.dumps(doc), encoding="utf-8")
    assert tine(monkeypatch, "verify-report", "check", "r1.json") == 4
    assert tine(monkeypatch, "verify-report", "check", "r1.json", "--allow-unsigned") == 0
    assert "not evidence" in capsys.readouterr().out


def test_sign_key_needs_report_and_timestamp_needs_sign_key(room, monkeypatch):
    key, _ = _keys(room)
    assert tine(monkeypatch, "verify", "run.tine", "--offline", "--sign-key", str(key)) == 2
    assert tine(monkeypatch, "verify", "run.tine", "--offline", "--report", "r.json",
                "--timestamp") == 2  # fmt: skip
    assert tine(monkeypatch, "verify", "run.tine", "--sign-key", str(key)) == 1  # needs --offline


# --------------------------------------------------------------------------- #
# in-toto replay/v1
# --------------------------------------------------------------------------- #


def test_replay_predicate_validates(room, monkeypatch):
    key, pub = _keys(room)
    argv = ("replay", "run.tine", "--verify", "--attest", "a.intoto.jsonl", "--attest-key")
    assert tine(monkeypatch, *argv, str(key)) == 0
    envelope = json.loads((room / "a.intoto.jsonl").read_text(encoding="utf-8"))
    statement = verify_envelope(envelope, pub.read_text(encoding="ascii"))
    assert statement["predicateType"] == PREDICATE_TYPE
    predicate = statement["predicate"]
    assert validate_predicate(predicate) == [] and predicate["result"]["reproduced"] is True
    broken = {**predicate, "mode": "live", "result": {**predicate["result"], "reproduced": 1}}
    assert len(validate_predicate(broken)) == 2
    _, other = _keys(room, "other")
    with pytest.raises(ValueError):
        verify_envelope(envelope, other.read_text(encoding="ascii"))


def test_replay_attest_needs_verify_and_a_key(room, monkeypatch):
    assert tine(monkeypatch, "replay", "run.tine", "--attest", "a.jsonl") == 1
    assert tine(monkeypatch, "replay", "run.tine", "--verify", "--attest", "a.jsonl") == 2


# --------------------------------------------------------------------------- #
# custody on opentine-log/1
# --------------------------------------------------------------------------- #


@pytest.fixture
def repo(room, monkeypatch) -> Path:
    assert repo_tine(monkeypatch, "init") == 0
    return room


def test_custody_chain_verifies_with_a_signing_time(repo, monkeypatch, capsys):
    key, pub = _keys(repo)
    assert repo_tine(monkeypatch, "custody", "record", "received", "sha256:" + "ab" * 32,
                "--sign-key", str(key), "--actor", "alice", "--json") == 0  # fmt: skip
    first = json.loads(capsys.readouterr().out)
    assert repo_tine(monkeypatch, "custody", "record", "exported", "run.tine",
                "--sign-key", str(key), "--actor", "bob") == 0  # fmt: skip
    tsa, tsa_key = _ca(repo)
    (repo / "t.tsr").write_bytes(token(first["sig_bound"].encode(), tsa, tsa_key))
    assert repo_tine(monkeypatch, "custody", "record", "timestamp", first["sig_bound"],
                "--token", "t.tsr", "--sign-key", str(key)) == 0  # fmt: skip
    capsys.readouterr()
    argv = ("custody", "verify", "--pubkey", str(pub), "--tsa-roots", "ca.pem", "--json")
    assert repo_tine(monkeypatch, *argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["size"] == 3
    assert [r["action"] for r in result["records"]] == ["received", "exported", "timestamp"]
    assert result["records"][0]["signing_time"]
    assert repo_tine(monkeypatch, "custody", "log") == 0
    _, other = _keys(repo, "other")
    assert repo_tine(monkeypatch, "custody", "verify", "--pubkey", str(other)) == 4


def test_custody_tampering_is_detected(repo, monkeypatch):
    key, _ = _keys(repo)
    for actor in ("alice", "bob"):
        assert repo_tine(monkeypatch, "custody", "record", "received", "x",
                    "--sign-key", str(key), "--actor", actor) == 0  # fmt: skip
    bundle = _custody.log_root(repo / ".tine") / "tile" / "entries" / "000.p" / "2"
    raw = bundle.read_bytes()
    bundle.write_bytes(raw.replace(b'"bob"', b'"eve"'))
    assert repo_tine(monkeypatch, "custody", "verify") == 4


def test_custody_refuses_a_token_for_an_unknown_signature(repo, monkeypatch):
    key, _ = _keys(repo)
    tsa, tsa_key = _ca(repo)
    fake = sidecar.SIG_PREFIX + "00" * 32
    (repo / "t.tsr").write_bytes(token(fake.encode(), tsa, tsa_key))
    assert repo_tine(monkeypatch, "custody", "record", "timestamp", fake, "--token", "t.tsr",
                "--sign-key", str(key)) == 1  # fmt: skip
    assert repo_tine(monkeypatch, "custody", "record", "seized", "x", "--sign-key", str(key)) == 1
