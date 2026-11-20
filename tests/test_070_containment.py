"""0.69: sandbox policy evidence, `tine containment check`, advisory detectors, probe fixture."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _containment, _containment_detect, _schemas
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.containment_fixture import EXPECTED, POLICY, PROBES, probe_run
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

RUNNER = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "runner.hex"
    path.write_bytes(RUNNER.private_bytes_raw().hex().encode("ascii"))
    return path


def _pin_runner(repo):
    pub = RUNNER.public_key().public_bytes_raw().hex()
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\nrunner = ["{pub}"]\n'.encode()
    )
    pin_roles(repo.path)


def _cli(capsys, *argv):
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    return code, body


def test_the_policy_digest_is_canonical():
    shuffled = {**POLICY, "network_allowlist": ["FILES.pythonhosted.org", "pypi.org", "pypi.org"],
                "mounts": list(reversed(POLICY["mounts"]))}  # fmt: skip
    assert _containment.digest(shuffled) == _containment.digest(POLICY)
    assert _containment.digest({**POLICY, "privileges": ["CAP_SYS_ADMIN"]}) != _containment.digest(
        POLICY
    )
    for bad in ({**POLICY, "extra": 1}, {**POLICY, "image_digest": "latest"},
                {**POLICY, "mounts": [{"path": "/", "mode": "rwx"}]}):  # fmt: skip
        with pytest.raises(ValueError):
            _containment.canonical(bad)


def test_check_passes_on_the_declared_digest_and_fails_on_another(repo, tmp_path, capsys,
                                                                   key_file):  # fmt: skip
    run = repo.put_run(probe_run(tmp_path)).run_id
    policy = tmp_path / "policy.json"
    policy.write_bytes(json.dumps(POLICY).encode())
    base = ("--repo", str(repo.path.parent), "--json")
    code, body = _cli(capsys, "containment", "check", run, "--policy", str(policy), *base)
    assert code == 1 and body["findings"][0]["code"] == "fail:sandbox-policy-mismatch"
    code, body = _cli(capsys, "containment", "record", run, "--policy", str(policy),
                      "--key", str(key_file), *base)  # fmt: skip
    assert body["policy_digest"] == _containment.digest(POLICY)
    code, body = _cli(capsys, "containment", "check", run, "--policy", str(policy), *base)
    assert code == 0 and body["ok"]
    assert [f["code"] for f in body["findings"]] == ["advisory:containment.runner-unpinned"]
    _pin_runner(repo)
    code, body = _cli(capsys, "containment", "check", run, "--policy", str(policy), *base)
    assert body["findings"] == [] and body["policies"][0]["verification"] == "verified"
    other = _containment.digest({**POLICY, "network_allowlist": ["*"[:0] + "example.org"]})
    code, body = _cli(capsys, "containment", "check", run, "--digest", other, *base)
    assert code == 1 and body["findings"][0]["code"] == "fail:sandbox-policy-mismatch"
    with pytest.raises(HoldError):
        release(repo, body["policies"][0]["record"])


def test_a_signer_field_naming_another_key_is_a_mismatch(repo, tmp_path, monkeypatch):
    from opentine import _containment_records

    run = repo.put_run(probe_run(tmp_path)).run_id
    monkeypatch.setattr(_containment_records, "fingerprint", lambda key: "sha256:" + "0" * 64)
    _containment.record(repo, run, POLICY, RUNNER)
    body = _containment.check(repo, run, _containment.digest(POLICY))
    assert not body["ok"]
    assert "not signed by the key" in body["findings"][0]["message"]


def test_the_probe_fixture_is_all_recorded_and_flagged(repo, tmp_path, capsys, key_file):
    run = probe_run(tmp_path)
    found = _containment_detect.scan_run(run, POLICY["network_allowlist"])
    steps = {i: s for i, s in enumerate(run.steps)}
    by_probe: dict[str, set[str]] = {}
    for f in found:
        probe = (steps[f["step"]].outputs or {}).get("probe")
        assert probe is not None, f"benign step {f['step']} flagged: {f}"
        by_probe.setdefault(probe, set()).add(f["category"])
    assert by_probe == EXPECTED and set(by_probe) == set(PROBES)
    assert all(f["code"].startswith("advisory:") for f in found)  # D12: advisory only
    spawned = [
        s.outputs for s in run.steps if (s.outputs or {}).get("probe") == "spawn-unmonitored"
    ]
    assert spawned[0]["status"] == 0  # the harmless child ran and exited inside tmp_path
    run_id = repo.put_run(run).run_id
    _containment.record(repo, run_id, POLICY, RUNNER)
    base = ("--repo", str(repo.path.parent), "--json")
    code, body = _cli(capsys, "containment", "scan", run_id, "--key", str(key_file), *base)
    assert code == 0 and len(body["recorded"]) == len(found)
    held = _containment_detect.recorded(repo, run_id)
    assert {r["claim"]["category"] for r in held} == set().union(*EXPECTED.values())
    for row in held:
        assert row["signed"]
        assert _schemas.validate(row["claim"], "opentine-containment-finding-1")[1] == []
    code, again = _cli(capsys, "containment", "scan", run_id, "--key", str(key_file), *base)
    assert again["recorded"] == []  # a rescan records nothing twice
    code, strict = _cli(capsys, "containment", "scan", run_id, "--strict", *base)
    assert code == 1
    with pytest.raises(HoldError):
        release(repo, held[0]["oid"])


def test_without_a_policy_every_host_is_egress(tmp_path):
    hits = _containment_detect.scan_text("shell curl https://pypi.org/simple/", None)
    assert [h["category"] for h in hits] == ["egress"]
    assert _containment_detect.scan_text("shell curl https://pypi.org/x", ["pypi.org"]) == []
    assert (
        _containment_detect.scan_text("shell ssh deploy@build.example.org", ["*.example.org"]) == []
    )


def test_the_gate_records_findings_without_changing_its_decision(repo):
    from opentine._monitor_gate import Gate
    from opentine._monitors import parse

    monitor = {"id": "rules", "kind": "rule", "threshold": 0.5, "rules": []}
    cfg = parse({"version": 1, "mode": "gate", "deadline_ms": 100, "monitor": monitor})
    gate = Gate(cfg, repo=repo, key=RUNNER, agent="coder")
    decision = gate.decide("tools/call", {"name": "shell", "arguments": {"cmd": PROBES["persist"]}})
    assert decision["outcome"] == "forward"
    held = _containment_detect.recorded(repo)
    assert [r["claim"]["category"] for r in held] == ["persistence"] and held[0]["signed"]


def test_the_runner_role_is_guarded_against_the_optimizer_key():
    from opentine import _key_roles

    key = _key_roles.normalize_key("cd" * 32)
    found = _key_roles.lint({"optimizer": [key], "runner": [key]})
    assert any(f["code"] == "fail:key-separation.shared" and f["role"] == "runner"
               for f in found)  # fmt: skip
