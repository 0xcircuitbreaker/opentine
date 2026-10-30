"""in-toto Statement v1 in a DSSE envelope: ``tine export --format intoto``.

Driven in-process through ``opentine.cli.main`` (no subprocess, no binary).
The claims: an envelope verifies only under a key the caller trusts and only
for the exact run bytes it names; any edit to payload, signature or subject
fails closed; and the predicate is content-free -- no prompt, completion or
secret leaves the run in it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._signing_keys import generate_ed25519
from opentine._signing_pins import key_fingerprint
from opentine.did_key import did_from_public
from opentine.intoto import (
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    build_statement,
    check_subject,
    pae,
    sign_statement,
    verify_envelope,
)

SECRET_PROMPT = "summarise the merger memo for ACME-PROJECT-NIGHTJAR"
SECRET_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _run(path: Path) -> Run:
    run = Run(id="intoto_src", model_info="mock-model", user_prompt=SECRET_PROMPT)
    think = run.add_step(StepKind.think, {"text": f"token {SECRET_TOKEN}"})
    run.add_step(
        StepKind.model,
        {"prompt": SECRET_PROMPT},
        outputs={"text": "NIGHTJAR answer text"},
        parent_id=think.id,
        model_info="mock-model",
        provider="mockprov",
        cost=0.25,
        usage={"input": 10, "output": 5},
    )
    run.status = RunStatus.completed
    run.save(path)
    return run


@pytest.fixture
def ws(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    _run(tmp_path / "run.tine")
    seed, public = generate_ed25519()
    (tmp_path / "k.key").write_text(seed + "\n")
    (tmp_path / "k.pub").write_text(public + "\n")
    return tmp_path


def _digest(path: Path) -> str:
    return Run.verify_integrity(path).actual


def _envelope(ws: Path) -> dict:
    statement = build_statement(Run.load(ws / "run.tine"), _digest(ws / "run.tine"))
    return sign_statement(statement, (ws / "k.key").read_text())


def _pub(ws: Path) -> str:
    return (ws / "k.pub").read_text().strip()


def _statement(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))


def test_pae_matches_dsse_spec() -> None:
    assert pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_roundtrip_and_shape(ws: Path) -> None:
    envelope = _envelope(ws)
    assert envelope["payloadType"] == PAYLOAD_TYPE
    [sig] = envelope["signatures"]
    assert sig["keyid"] == did_from_public(_pub(ws))
    statement = _statement(envelope)
    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    assert statement["subject"] == [
        {"name": "intoto_src", "digest": {"sha256": _digest(ws / "run.tine")}}
    ]
    predicate = statement["predicate"]
    assert predicate["step_count"] == 2
    assert predicate["providers"] == ["mockprov"]
    assert predicate["usage"] == {"total_tokens": 15, "total_cost_usd": 0.25}
    result = verify_envelope(envelope, public_key=_pub(ws))
    assert result.ok and result.status == "verified"
    assert check_subject(result.statement, ws / "run.tine") is None


def test_no_content_or_secret_in_predicate(ws: Path) -> None:
    body = base64.b64decode(_envelope(ws)["payload"]).decode()
    for needle in ("NIGHTJAR", "merger", SECRET_TOKEN, "answer text"):
        assert needle not in body


def test_fork_lineage_recorded(ws: Path) -> None:
    run = Run.load(ws / "run.tine")
    child = run.fork(run.steps[0].id)
    child.save(ws / "child.tine")
    statement = build_statement(child, _digest(ws / "child.tine"))
    assert statement["predicate"]["lineage"]["forked_from"] == "intoto_src"


def test_tampered_payload_signature_and_wrong_key_fail(ws: Path) -> None:
    envelope = _envelope(ws)
    statement = _statement(envelope)
    statement["predicate"]["step_count"] = 99
    forged = dict(envelope, payload=base64.b64encode(json.dumps(statement).encode()).decode())
    assert verify_envelope(forged, public_key=_pub(ws)).status == "mismatch"
    sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    sig[0] ^= 1
    bad = dict(
        envelope, signatures=[{**envelope["signatures"][0], "sig": base64.b64encode(sig).decode()}]
    )
    assert verify_envelope(bad, public_key=_pub(ws)).status == "mismatch"
    _, other = generate_ed25519()
    assert verify_envelope(envelope, public_key=other).status == "mismatch"
    assert verify_envelope(envelope).status == "no-key"  # nothing trusted: fail closed
    assert verify_envelope(dict(envelope, payloadType="text/plain")).status == "error"


def test_pin_and_tofu(ws: Path) -> None:
    envelope = _envelope(ws)
    fpr = key_fingerprint(bytes.fromhex(_pub(ws)))
    assert verify_envelope(envelope, pins=frozenset({fpr})).status == "verified"
    assert verify_envelope(envelope, pins=frozenset({"sha256:" + "0" * 64})).status == "no-key"
    assert verify_envelope(envelope, trust_embedded=True).status == "verified-tofu"


def test_subject_mismatch(ws: Path) -> None:
    result = verify_envelope(_envelope(ws), public_key=_pub(ws))
    other = Run(id="other", model_info="m")
    other.save(ws / "other.tine")
    assert "does not match" in check_subject(result.statement, ws / "other.tine")


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def test_cli_happy_path_and_json(ws: Path, capsys) -> None:
    assert _cli("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "k.key",
                "--output", "a.intoto.jsonl") == 0  # fmt: skip
    capsys.readouterr()
    assert _cli("verify", "run.tine", "--attestation", "a.intoto.jsonl", "--pubkey", "k.pub",
                "--json") == 0  # fmt: skip
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["signature"]["status"] == "verified"
    assert payload["signature"]["keyid"] == did_from_public(_pub(ws))
    assert payload["predicate_type"] == PREDICATE_TYPE
    assert payload["subject_digest"] == {"sha256": _digest(ws / "run.tine")}
    assert _cli("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "k.key") == 0
    line = capsys.readouterr().out.strip()
    assert verify_envelope(json.loads(line), public_key=_pub(ws)).ok


def test_cli_failures_exit_nonzero(ws: Path, capsys) -> None:
    assert _cli("export", "run.tine", "--format", "intoto") == 1  # no key: no envelope
    assert _cli("export", "run.tine", "--ed25519-key-file", "k.key") == 1  # not intoto
    assert _cli("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "k.key",
                "--output", "a.intoto.jsonl") == 0  # fmt: skip
    assert _cli("verify", "run.tine", "--attestation", "a.intoto.jsonl") == 1  # no key
    assert _cli("verify", "run.tine", "--attestation", "a.intoto.jsonl",
                "--key-file", "k.key") == 1  # fmt: skip
    _, other = generate_ed25519()
    (ws / "other.pub").write_text(other)
    assert _cli("verify", "run.tine", "--attestation", "a.intoto.jsonl",
                "--pubkey", "other.pub") == 1  # fmt: skip
    Run(id="other", model_info="m").save(ws / "other.tine")
    capsys.readouterr()
    assert _cli("verify", "other.tine", "--attestation", "a.intoto.jsonl",
                "--pubkey", "k.pub", "--json") == 1  # fmt: skip
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False and payload["signature"]["status"] == "verified"
    assert "does not match" in payload["subject"]["reason"]
    (ws / "bad.intoto.jsonl").write_text("not json\n")
    assert _cli("verify", "run.tine", "--attestation", "bad.intoto.jsonl",
                "--pubkey", "k.pub") == 1  # fmt: skip
