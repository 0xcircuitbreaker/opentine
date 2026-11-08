"""0.45 pre-push redaction gate, ``tine redact check`` and ``tine doctor --bundle``."""

from __future__ import annotations

import json
import socket

import pytest

from opentine import _push_gate, cli
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository._oplog import read_ops

FAKE_KEY = b"OPENAI_API_KEY=sk-proj-" + b"Zq7Xw2Lr9Tb4Nc8Vm1Hs6Jd3Kf5Gp0Ya"
HMAC_KEY = "ab" * 32
URL = "https://tine.example.invalid/v1"


def _run(run_id: str, text: str = "hello") -> Run:
    run = Run(id=run_id, model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": text})
    return run


@pytest.fixture
def clean(tmp_path):
    store = Repo.init(tmp_path / "store")
    store.put_run(_run("clean"), ref="heads/main")
    return store


@pytest.fixture
def offline(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("touched the network")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def test_scan_finds_the_fake_key_and_names_only_the_oid(clean):
    blob = clean.put("blob", FAKE_KEY, redact=False)
    hits = _push_gate.scan(clean, clean.iter_oids())
    assert hits == [{"oid": blob, "kind": "blob"}]
    assert b"sk-proj" not in json.dumps(hits).encode()


def test_clean_repository_has_no_findings(clean):
    assert _push_gate.scan(clean, clean.iter_oids()) == []


def test_enforce_refuses_outgoing_secret(clean, monkeypatch):
    blob = clean.put("blob", FAKE_KEY, redact=False)
    monkeypatch.setattr(_push_gate, "outgoing_oids", lambda *_a: {blob})
    with pytest.raises(ValueError, match="push refused") as info:
        _push_gate.enforce(clean, "origin", ["heads/main"], None)
    assert "sk-proj" not in str(info.value) and blob in str(info.value)
    with pytest.raises(ValueError, match="non-empty"):
        _push_gate.enforce(clean, "origin", ["heads/main"], "  ")
    assert _push_gate.enforce(clean, "origin", ["heads/main"], "fixture") == [
        {"oid": blob, "kind": "blob"}
    ]


def test_push_of_secret_is_refused_before_any_connection(tmp_path, capsys, monkeypatch, offline):
    store = Repo.init(tmp_path / "store")
    store.put_run(_run("leak", text=FAKE_KEY.decode()), ref="heads/main")
    blob = store.put("blob", FAKE_KEY, redact=False)
    original = _push_gate.outgoing_oids  # make the leaked blob part of the outgoing pack
    monkeypatch.setattr(_push_gate, "outgoing_oids", lambda *a: original(*a) | {blob})
    with pytest.raises(SystemExit) as info:
        cli.main(["push", URL, "--repo", str(store.path)])
    assert info.value.code != 0
    err = capsys.readouterr().err
    assert "push refused" in err and blob in err and "sk-proj" not in err


def test_allow_unredacted_reason_lands_in_the_op_log(clean, monkeypatch):
    from opentine.repository._oplog import operation

    blob = clean.put("blob", FAKE_KEY, redact=False)
    monkeypatch.setattr(_push_gate, "outgoing_oids", lambda *_a: {blob})
    with operation("push"):
        _push_gate.enforce(clean, "origin", ["heads/main"], "fixture")
        clean.put_run(_run("next"), ref="heads/main")
    ops = read_ops(clean.path)
    assert ops[-1]["note"] == "allow-unredacted: fixture (1 object(s))"


def test_run_report_is_signed_and_verifies(clean):
    from opentine._signing_keys import hmac_key_from_file

    run = clean.read_ref("heads/main")
    report = _push_gate.run_report(clean, run)
    assert report["clean"] and report["ruleset"] == "opentine-redaction/2"
    assert report["objects"] > 1
    key_file = clean.path.parent / "k.hex"
    key_file.write_text(HMAC_KEY)
    key = hmac_key_from_file(str(key_file))
    signed = _push_gate.sign(report, key, algorithm="hmac-sha256", key_id="t")
    assert _push_gate.verify(signed, hmac_key=key).ok
    tampered = {**signed, "clean": False}
    assert not _push_gate.verify(tampered, hmac_key=key).ok


def test_redact_check_cli_json(clean, capsys):
    cli.main(["redact", "check", "--repo", str(clean.path), "--json"])
    body = json.loads(capsys.readouterr().out)
    assert body["clean"] is True and len(body["reports"]) == 1


def test_doctor_bundle_holds_no_secret(tmp_path, monkeypatch, capsys, offline):
    monkeypatch.setenv("OPENTINE_TOKEN", FAKE_KEY.decode())
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "cfg").as_posix())
    out = tmp_path / "bundle.json"
    cli.main(["doctor", "--repo", str(tmp_path), "--bundle", str(out), "--json"])
    body = json.loads(capsys.readouterr().out)
    assert body["kind"] == "opentine.doctor"
    data = out.read_bytes()
    assert b"sk-proj" not in data and b"OPENTINE_TOKEN" in data
    checks = {row["check"] for row in json.loads(data)["checks"]}
    assert {"opentine", "python", "agent-keys", "git-hooks", "harnesses"} <= checks


def test_doctor_bundle_refuses_surviving_secret(monkeypatch):
    from opentine import _doctor

    monkeypatch.setattr("opentine.redaction.redact_value", lambda value: value)
    with pytest.raises(ValueError, match="not written"):
        _doctor.bundle({"detail": FAKE_KEY.decode()})
