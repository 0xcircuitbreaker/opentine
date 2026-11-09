"""0.49: ``tine audit-kit build|verify``, the air-gapped audit kit.

* A kit built from a signed run carries the pyz, the offline TS page, the run
  crate, a ``replay/v1`` attestation, the pinned witness set, the evidence and a
  printed report, and ``verify`` passes on the directory and on its zip with the
  network refused (the offline guard is entered for every in-process check).
* The kit's own ``tine-verify.pyz`` and ``ae/verify_kit.py`` pass in a separate
  ``python -I`` process; the page's script re-checks the runs under Node.
* Tampering with any file, an unsafe zip and a bad witness key are refused; a
  bundle builds a kit too.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._audit_kit_check import offline_checks, unpack, verify_kit
from opentine._audit_kit_page import SCRIPT_END, SCRIPT_START
from opentine.repository._tlog_cosign import witness_vkey
from opentine.signing import HAS_ED25519, generate_ed25519

pytestmark = [
    pytest.mark.skipif(not HAS_ED25519, reason="signing needs the crypto extra"),
    pytest.mark.filterwarnings("ignore::opentine._key_store.PlaintextKeyWarning"),
]
NODE = shutil.which("node")


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENTINE_HOME", str(tmp_path / "home"))
    return tmp_path


def _key(room: Path, name: str) -> tuple[Path, Path]:
    private, public = generate_ed25519()
    (room / name).write_text(private, encoding="ascii")
    (room / name).chmod(0o600)
    (room / f"{name}.pub").write_text(public + "\n", encoding="ascii")
    return room / name, room / f"{name}.pub"


def _signed(room: Path, name: str = "run") -> tuple[Path, Path, Path]:
    run = Run(user_prompt="hello", model_info="model-a")
    run.add_step(StepKind.model, {"messages": [{"role": "user", "content": "hi"}]}, {"t": "yo"})
    run.status = RunStatus.completed
    path = room / f"{name}.tine"
    run.save(path)
    key, pub = _key(room, "k")
    cli.main(["sign", str(path), "--algorithm", "ed25519", "--ed25519-key-file", str(key),
              "--save", str(path), "--overwrite"])  # fmt: skip
    return path, key, pub


def _vkey(name: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return witness_vkey(name, Ed25519PrivateKey.generate().public_key().public_bytes_raw())


def _build(capsys, room: Path, *extra: str) -> dict:
    path, key, pub = _signed(room)
    capsys.readouterr()
    argv = ["audit-kit", "build", str(path), "--out", "kit", "--pubkey", str(pub),
            "--attest-key", str(key), "--witness", _vkey("w1"), "--witness", _vkey("w2"),
            "--quorum", "2-of-2", "--operator", "tester", "--json", *extra]  # fmt: skip
    code = 0
    try:
        cli.main(argv)
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = json.loads(capsys.readouterr().out)
    assert code == 0, out
    return out


def test_build_writes_every_component_and_verify_passes_offline(capsys, room):
    summary = _build(capsys, room, "--zip")
    assert summary["ok"] and summary["zip"] == "kit.zip"
    kit = room / "kit"
    for name in ("tine-verify.pyz", "verify.html", "REPORT.md", "report.html", "kit.json",
                 "SHA256SUMS", "README.md", "evidence/MANIFEST.sha256", "evidence/custody.jsonl",
                 "attestations/replay.intoto.jsonl", "trust/witnesses.json", "ae/README.md",
                 "ae/verify_kit.py", "ae/verify.sh", "ae/verify.ps1", "ae/reproduce.sh",
                 "evidence/trust/pubkey.pub", "crate/run/ro-crate-metadata.json"):  # fmt: skip
        assert (kit / name).is_file(), name
    names = {c["name"]: c["outcome"] for c in summary["checks"]}
    assert names["replay"] == names["witnesses"] == names["crate:run.tine"] == "pass"
    assert "Artifacts Evaluated: Functional" in (kit / "ae/README.md").read_text("utf-8")
    assert "PASS" in (kit / "REPORT.md").read_text("utf-8")
    for target in (kit, room / "kit.zip"):
        result = verify_kit(target)
        assert result["ok"], [c for c in result["checks"] if c["outcome"] != "pass"]
        outcomes = {c["name"]: c["outcome"] for c in result["checks"]}
        assert set(outcomes.values()) == {"pass"}, outcomes
        for name in ("sums", "evidence", "replay", "witnesses", "pyz", "page", "summary"):
            assert outcomes[name] == "pass"


def test_the_zip_is_deterministic(capsys, room):
    _build(capsys, room, "--zip")
    first = (room / "kit.zip").read_bytes()
    from opentine._audit_kit import write_zip

    write_zip(room / "kit", room / "again.zip")
    assert (room / "again.zip").read_bytes() == first


def test_verify_json_and_pyz_subprocess(capsys, room):
    _build(capsys, room)
    with pytest.raises(SystemExit) as done:
        cli.main(["audit-kit", "verify", "kit", "--pyz", "--json"])
        raise SystemExit(0)
    assert done.value.code in (0, None)
    result = json.loads(capsys.readouterr().out)
    assert result["command"] == "audit-kit-verify" and result["ok"]
    assert {c["name"]: c["outcome"] for c in result["checks"]}["pyz-run"] == "pass"


def test_the_ae_script_passes_with_the_standard_library_alone(capsys, room):
    _build(capsys, room)
    done = subprocess.run([sys.executable, "-I", "ae/verify_kit.py"], cwd=room / "kit",
                          capture_output=True, text=True, timeout=300)  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip().endswith("PASS")


@pytest.mark.parametrize("victim", ["evidence/runs/run.tine", "REPORT.md", "verify.html"])
def test_tampering_with_any_file_fails(capsys, room, victim):
    _build(capsys, room)
    path = room / "kit" / victim
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(bytes(data))
    result = verify_kit(room / "kit")
    assert not result["ok"]
    assert {c["name"]: c["outcome"] for c in result["checks"]}["sums"] == "fail"


def test_an_unlisted_file_fails(capsys, room):
    _build(capsys, room)
    (room / "kit" / "extra.txt").write_text("x", encoding="utf-8")
    assert not verify_kit(room / "kit")["ok"]


def test_an_unsafe_zip_is_refused(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("kit/../../escape.txt", "x")
    with pytest.raises(ValueError, match="unsafe"):
        unpack(archive, tmp_path / "out")


def test_the_checks_run_inside_the_offline_guard(capsys, room, monkeypatch):
    _build(capsys, room)
    from opentine import _offline_guard

    entered = []
    real = _offline_guard.no_network

    def spy():
        entered.append(True)
        return real()

    monkeypatch.setattr(_offline_guard, "no_network", spy)
    assert all(c["outcome"] == "pass" for c in offline_checks(room / "kit"))
    assert entered == [True]


def test_a_bad_witness_key_is_refused(capsys, room):
    path, _key_file, pub = _signed(room)
    with pytest.raises(SystemExit):
        cli.main(["audit-kit", "build", str(path), "--out", "kit", "--pubkey", str(pub),
                  "--witness", "not-a-key"])  # fmt: skip
    assert "witness" in capsys.readouterr().err.lower()


def test_a_bundle_builds_a_kit(capsys, room):
    from opentine import _bundle
    from opentine.repo import Repo

    repo = Repo.init(room / "src")
    run = Run(user_prompt="b", model_info="m")
    run.add_step(StepKind.think, {"text": "x"}, {"a": 1})
    repo.put_run(run, ref="heads/main")
    (room / "runs.bundle").write_bytes(_bundle.create(repo, ["heads/main"]))
    cli.main(["audit-kit", "build", "runs.bundle", "--out", "kit", "--operator", "t", "--json"])
    summary = json.loads(capsys.readouterr().out)
    assert summary["source"]["kind"] == "bundle" and len(summary["runs"]) == 1
    assert {c["name"]: c["outcome"] for c in summary["checks"]}["bundle"] == "pass"
    assert (room / "kit" / "source" / "runs.bundle").is_file()
    assert verify_kit(room / "kit")["ok"]


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_the_offline_page_verifies_its_runs_under_node(capsys, room):
    _build(capsys, room)
    html = (room / "kit" / "verify.html").read_text(encoding="utf-8")
    assert not re.search(r"https?://[^\s\"'<>]*\.(?:js|css)\b", html.split(SCRIPT_START)[0])
    script = html.split(SCRIPT_START, 1)[1].split(SCRIPT_END, 1)[0]
    runner = room / "page.mjs"
    runner.write_text(script + "\nglobalThis.tineKitResults.then((r) => "
                      "console.log(JSON.stringify(r)));\n", encoding="utf-8")  # fmt: skip
    done = subprocess.run([NODE, str(runner)], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    rows = json.loads(done.stdout)
    assert len(rows) == 1 and rows[0]["ok"] and rows[0]["digest_match"], rows
    assert rows[0]["signature"] in ("verified-tofu", "verified")
