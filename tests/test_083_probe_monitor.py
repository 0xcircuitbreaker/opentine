"""0.83: probe monitors record probe, checkpoint, layer, threshold and calibration.

1. A probe applied to activations from another checkpoint fails with the existing
   ``digest.mismatch`` code (library, ``tine interp score`` exit 4, and the gate,
   which fails closed).
2. Calibration evidence is signed and held; ``tine interp check`` reports a probe
   or threshold swapped after calibration, a missing calibration, and a
   calibration signed by an optimizer key.
3. On a seeded fixture the calibrated probe separates planted positives: counted,
   never timed.
"""

from __future__ import annotations

import hashlib
import json
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _interp_custody as ic
from opentine import _probe_monitor as pm
from opentine import _schemas
from opentine._monitor_gate import Gate
from opentine._monitors import MonitorError, parse
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"runner": 0x81, "monitor": 0x82, "optimizer": 0x83}
CKPT = "sha256:" + hashlib.sha256(b"model a").hexdigest()
OTHER = "sha256:" + hashlib.sha256(b"model b").hexdigest()
WIDTH = 8


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


def _probe(scale: float = 4.0) -> bytes:
    doc = {"format": pm.FORMAT, "layer": 12, "weights": [scale] + [0.0] * (WIDTH - 1),
           "bias": -scale / 2}  # fmt: skip
    return json.dumps(doc, sort_keys=True).encode("utf-8")


def _samples(seed: int, n: int = 200) -> list[dict]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        label = i % 2 == 0
        first = (1.0 if label else 0.0) + rng.uniform(-0.3, 0.3)
        out.append({"activations": [first] + [rng.uniform(-1, 1) for _ in range(WIDTH - 1)],
                    "label": label})  # fmt: skip
    return out


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [_fpr("runner")], "monitor": [_fpr("monitor"), _fpr("optimizer")],
             "optimizer": [_fpr("optimizer")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    stored = ic.store(repo, _probe(), kind="probe-weights", checkpoint=CKPT, key=_key("runner"),
                      layer=12)  # fmt: skip
    probe = stored["claim"]["digest"]
    cal = pm.calibrate(repo, probe, _key("monitor"), threshold=0.5, samples=_samples(1))
    (tmp_path / "probe.json").write_bytes(_probe())
    return {"repo": repo, "where": repo.path.parent.as_posix(), "tmp": tmp_path, "probe": probe,
            "calibration": cal["record"], "cal": cal["claim"]}  # fmt: skip


def _config(room, **over) -> str:
    section = {"id": "p1", "kind": "probe", "probe": room["probe"],
               "probe_file": (room["tmp"] / "probe.json").as_posix(), "checkpoint_digest": CKPT,
               "layer": 12, "threshold": 0.5, "calibration": room["calibration"],
               **over}  # fmt: skip
    lines = ["version = 1", 'mode = "gate"', "fail_closed = true", "[monitor]"]
    lines += [f"{k} = {json.dumps(v)}" for k, v in section.items()]
    path = room["tmp"] / "monitor.toml"
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return path.as_posix()


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert "error" in body or _schemas.validate_output(body) == []
    return code, body


def test_the_calibration_records_probe_checkpoint_layer_threshold_and_rates(room):
    claim = room["cal"]
    assert (claim["probe"], claim["checkpoint"], claim["layer"]) == (room["probe"], CKPT, 12)
    assert (claim["n"], claim["positives"], claim["negatives"]) == (200, 100, 100)
    assert claim["tpr"] >= 0.95 and claim["fpr"] <= 0.05


def test_planted_positives_are_caught_in_at_least_95_of_100_seeds(room):
    monitor = parse({"version": 1, "monitor": {
        "id": "p1", "kind": "probe", "probe": room["probe"],
        "probe_file": (room["tmp"] / "probe.json").as_posix(), "checkpoint_digest": CKPT,
        "layer": 12, "threshold": 0.5, "calibration": room["calibration"]}})["monitor"]  # fmt: skip
    caught = false_alarms = 0
    for seed in range(100):
        batch = _samples(1000 + seed, n=20)
        hits = [monitor.score({"checkpoint_digest": CKPT, "activations": s["activations"]})
                ["score"] >= 0.5 for s in batch]  # fmt: skip
        caught += all(h for h, s in zip(hits, batch, strict=True) if s["label"])
        false_alarms += sum(h for h, s in zip(hits, batch, strict=True) if not s["label"])
    assert caught >= 95
    assert false_alarms <= 0.05 * 100 * 10


def test_a_probe_on_another_checkpoint_fails_with_digest_mismatch(room, capsys):
    config = _config(room)
    monitor = parse({"version": 1, "monitor": {"id": "p", "kind": "probe", "probe": room["probe"],
        "probe_file": (room["tmp"] / "probe.json").as_posix(), "checkpoint_digest": CKPT,
        "layer": 12, "calibration": room["calibration"]}})["monitor"]  # fmt: skip
    with pytest.raises(pm.ProbeMismatch) as caught:
        monitor.score({"checkpoint_digest": OTHER, "activations": [0.0] * WIDTH})
    assert caught.value.code == "digest.mismatch"
    request = room["tmp"] / "req.json"
    request.write_bytes(json.dumps({"checkpoint_digest": OTHER,
                                    "activations": [1.0] * WIDTH}).encode("utf-8"))  # fmt: skip
    code, body = _tine(capsys, "interp", "score", config, "--request", request.as_posix(),
                       "--repo", room["where"], "--json")  # fmt: skip
    assert code == 4 and body["reason"] == "digest.mismatch"
    request.write_bytes(json.dumps({"checkpoint_digest": CKPT,
                                    "activations": [1.0] * WIDTH}).encode("utf-8"))  # fmt: skip
    code, body = _tine(capsys, "interp", "score", config, "--request", request.as_posix(),
                       "--repo", room["where"], "--json")  # fmt: skip
    assert code == 0 and body["over"] and body["monitor"]["checkpoint"] == CKPT


def test_the_gate_reads_activations_from_meta_and_fails_closed_on_a_mismatch(room):
    from opentine._monitors import load

    gate = Gate(load(_config(room)), repo=room["repo"], key=_key("monitor"))
    meta = {"opentine/activations": {"checkpoint_digest": CKPT, "activations": [0.0] * WIDTH}}
    calm = gate.decide("tools/call", {"name": "ls", "arguments": {}, "_meta": meta})
    assert calm["outcome"] == "forward" and calm["claim"]["monitor"]["kind"] == "probe"
    meta["opentine/activations"]["checkpoint_digest"] = OTHER
    wrong = gate.decide("tools/call", {"name": "ls", "arguments": {}, "_meta": meta})
    assert (wrong["outcome"], wrong["claim"]["decided_by"]) == ("block", "error")
    assert wrong["claim"]["monitor"]["calibration"] == room["calibration"]


def test_a_probe_gate_must_fail_closed_and_name_its_calibration(room):
    section = {"id": "p", "kind": "probe", "probe": room["probe"], "layer": 12,
               "probe_file": (room["tmp"] / "probe.json").as_posix(), "checkpoint_digest": CKPT,
               "calibration": room["calibration"]}  # fmt: skip
    with pytest.raises(MonitorError, match="fails closed"):
        parse({"version": 1, "mode": "gate", "monitor": section})
    with pytest.raises(MonitorError, match="calibration"):
        parse({"version": 1, "monitor": {**section, "calibration": None}})


def test_check_detects_swaps_after_calibration(room, capsys):
    code, body = _tine(capsys, "interp", "check", _config(room), "--repo", room["where"],
                       "--json")  # fmt: skip
    assert (code, body["findings"]) == (0, [])
    code, body = _tine(capsys, "interp", "check", _config(room, threshold=0.3), "--repo",
                       room["where"], "--json")  # fmt: skip
    assert code == 1 and [f["code"] for f in body["findings"]] == ["probe.threshold-changed"]
    (room["tmp"] / "probe.json").write_bytes(_probe(scale=9.0))
    swapped = ic.digest(_probe(scale=9.0))
    code, body = _tine(capsys, "interp", "check", _config(room, probe=swapped), "--repo",
                       room["where"], "--json")  # fmt: skip
    assert code == 1 and [f["code"] for f in body["findings"]] == ["probe.swapped"]
    code, body = _tine(capsys, "interp", "check", _config(room), "--repo", room["where"],
                       "--json")  # fmt: skip
    assert code == 4 and body["reason"] == "digest.mismatch"  # the file no longer matches


def test_check_fails_closed_on_missing_or_optimizer_calibration(room, capsys):
    code, body = _tine(capsys, "interp", "check", _config(room, calibration="attestation:none"),
                       "--repo", room["where"], "--json")  # fmt: skip
    assert code == 1 and body["findings"][0]["code"] == "probe.calibration-missing"
    bad = pm.calibrate(room["repo"], room["probe"], _key("optimizer"), threshold=0.5,
                       samples=_samples(2))  # fmt: skip
    code, body = _tine(capsys, "interp", "check", _config(room, calibration=bad["record"]),
                       "--repo", room["where"], "--json")  # fmt: skip
    assert code == 1 and [f["code"] for f in body["findings"]] == ["probe.calibration-unverified"]


def test_query_shows_calibrations_verified_per_row(room, capsys):
    pm.calibrate(room["repo"], room["probe"], _key("optimizer"), threshold=0.5,
                 samples=_samples(3))  # fmt: skip
    assert _tine(capsys, "query", "index", "--rebuild", "--repo", room["where"], "--json")[0] == 0
    code, body = _tine(capsys, "query", "SELECT oid, probe, threshold FROM probe_calibrations",
                       "--repo", room["where"], "--verify", "--json")  # fmt: skip
    assert code == 0 and len(body["rows"]) == 2
    assert body["verification"]["counts"]["verified"] == 1
