"""0.45 pre-push gate: the paths the first tests did not reach.

The gate on the exact negotiated pack, the bundle (git) transport, the override
recorded in the op log on a real push, fail-closed scans, the fixture corpus,
and pinned vectors for the signed redaction report.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import socket
from pathlib import Path

import pytest

from opentine import _push_gate, cli
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository._oplog import read_ops
from tests.test_038_redaction_differential import SAMPLES

FAKE = "sk-proj-" + "Zq7Xw2Lr9Tb4Nc8Vm1Hs6Jd3Kf5Gp0Ya"
VECTORS = Path(__file__).parent / "fixtures" / "redaction_report" / "vectors.json"


def _run(run_id: str) -> Run:
    run = Run(id=run_id, model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "hello"})
    return run


@pytest.fixture
def store(tmp_path):
    repo = Repo.init(tmp_path / "store")
    repo.put_run(_run("clean"), ref="heads/main")
    return repo


@pytest.fixture
def offline(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise OSError("offline test: no connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def test_gate_refuses_every_secret_in_the_fixture_corpus(store):
    shells = ("{}", "export API_KEY={}", "Authorization: Bearer {}", '{{"auth": "{}"}}')
    oids = {store.put("blob", s.format(v).encode(), redact=False) for v in SAMPLES for s in shells}
    hits = {hit["oid"] for hit in _push_gate.scan(store, oids)}
    assert hits == oids
    with pytest.raises(ValueError, match="push refused"):
        _push_gate.Gate(store, None)(oids)


def test_an_unreadable_object_fails_closed(store, monkeypatch):
    oid = store.read_ref("heads/main")

    def broken(_oid):
        raise ValueError("corrupt")

    monkeypatch.setattr(store, "get", broken)
    assert _push_gate.scan(store, {oid}) == [{"oid": oid, "kind": "run"}]


def test_gate_sees_objects_the_tracking_ref_wrongly_claims_are_sent(store, monkeypatch):
    """The remote was reset: the offline estimate says nothing is new, the real pack differs."""
    from opentine.repository import client

    blob = store.put("blob", FAKE.encode(), redact=False)
    head = store.read_ref("heads/main")
    store.update_ref("remotes/origin/main", head, expected_old=None)
    gate = _push_gate.Gate(store, None)
    assert gate(_push_gate.outgoing_oids(store, "origin", ["heads/main"])) == []

    @contextlib.contextmanager
    def fake_client(*_a, **_k):
        yield object()

    def fake_json(_client, method, path, **_k):
        return 200, ({} if path.endswith("capabilities") else {"refs": {}})

    monkeypatch.setattr(client, "_client", fake_client)
    monkeypatch.setattr(client, "_request_json", fake_json)
    monkeypatch.setattr(client, "fitted_pack", lambda *_a, **_k: (b"", [head, blob]))
    monkeypatch.setattr(client, "_upload", lambda *_a, **_k: pytest.fail("uploaded"))
    with pytest.raises(ValueError, match="push refused"):
        client.push(store, "https://r.invalid/v1", tenant="t", gate=gate)


def test_allow_unredacted_on_a_real_push_is_logged_before_sending(store, monkeypatch, offline):
    blob = store.put("blob", FAKE.encode(), redact=False)
    original = _push_gate.outgoing_oids
    monkeypatch.setattr(_push_gate, "outgoing_oids", lambda *a: original(*a) | {blob})
    reason = f"rotated {FAKE}"
    with pytest.raises(SystemExit):  # the connection fails after the gate
        cli.main(
            [
                "push",
                "https://r.invalid/v1",
                "--repo",
                str(store.path),
                "--allow-unredacted",
                reason,
            ]
        )  # noqa: E501
    ops = read_ops(store.path)
    noted = [op for op in ops if op.get("note")]
    assert len(noted) == 1 and noted[0]["command"] == "push" and noted[0]["refs"] == []
    assert noted[0]["note"].startswith("allow-unredacted: rotated ")
    assert "Zq7Xw2Lr9" not in json.dumps(ops)  # the reason itself is redacted
    assert noted[0]["note"].endswith("(1 object(s))")


def test_undo_skips_a_note_only_entry(store, monkeypatch):
    from opentine._undo import find_op

    blob = store.put("blob", FAKE.encode(), redact=False)
    from opentine.repository._oplog import operation

    with operation("tag"):
        store.update_ref("heads/other", store.read_ref("heads/main"), expected_old=None)
    _push_gate.check(store, {blob}, "fixture")
    ops = read_ops(store.path)
    assert ops[-1]["refs"] == [] and find_op(ops, None)["command"] == "tag"


def test_dry_run_warns_that_the_push_would_be_refused(store, monkeypatch, capsys):
    blob = store.put("blob", FAKE.encode(), redact=False)
    original = _push_gate.outgoing_oids
    monkeypatch.setattr(_push_gate, "outgoing_oids", lambda *a: original(*a) | {blob})
    cli.main(["push", "https://r.invalid/v1", "--repo", str(store.path), "--dry-run"])
    assert "would be refused" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_bundle_push_over_git_is_gated(tmp_path, store):
    import subprocess

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", remote.as_posix()], check=True)
    leak = store.put_run(_run("leak"), ref="heads/leak")
    blob = store.put("blob", FAKE.encode(), redact=False)
    # Hang the leaked blob off a ref, so the bundle carries it.
    store.update_ref("tags/leak", blob, expected_old=None)
    assert leak
    args = ["bundle", "push", remote.as_posix(), "--repo", str(store.path)]
    with pytest.raises(SystemExit) as info:
        cli.main(args)
    assert info.value.code != 0
    cli.main([*args, "--allow-unredacted", "fixture"])
    assert any("allow-unredacted: fixture" in (op.get("note") or "") for op in read_ops(store.path))


def test_redaction_report_vectors():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    doc = json.loads(VECTORS.read_text("utf-8"))
    keys = {
        "hmac-sha256": bytes.fromhex(doc["hmac_key_hex"]),
        "ed25519": Ed25519PrivateKey.from_private_bytes(bytes.fromhex(doc["ed25519_seed_hex"])),
    }
    for case in doc["cases"]:
        report = case["report"]
        block = report["signature"]
        body = {k: v for k, v in report.items() if k != "signature"}
        header = {k: block.get(k) for k in ("alg", "key_id", "scheme", "signed_at", "signer")}
        assert _push_gate._message(body, header).hex() == case["message_hex"], case["id"]
        key = keys[block["alg"]]
        again = _push_gate.sign(
            body, key, algorithm=block["alg"], key_id=block["key_id"], signed_at=block["signed_at"]
        )
        assert again == report, case["id"]  # HMAC and Ed25519 are deterministic
        if block["alg"] == "hmac-sha256":
            assert _push_gate.verify(report, hmac_key=key).ok
            assert not _push_gate.verify({**report, "clean": True}, hmac_key=key).ok
        else:
            public = key.public_key()
            assert _push_gate.verify(report, public_key=public).ok
            assert not _push_gate.verify({**report, "objects": 4}, public_key=public).ok


def test_doctor_bundle_holds_no_corpus_secret_in_paths(tmp_path, monkeypatch, offline):
    from opentine import _doctor

    for sample in SAMPLES[:12]:
        folder = tmp_path / f"cfg-{sample.replace('/', '_')}"
        monkeypatch.setenv("XDG_CONFIG_HOME", folder.as_posix())
        monkeypatch.setenv("OPENTINE_TOKEN", sample)
        data = _doctor.bundle(_doctor.report(str(tmp_path)))
        assert sample.encode() not in data, sample
