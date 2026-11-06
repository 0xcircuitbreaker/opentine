"""0.39.0: ``tine-verify.pyz``, the offline verifier with no native code.

* The pure-Python Ed25519 routine passes RFC 8032 §7.1 and every Wycheproof
  ``ed25519_test`` vector (``tests/data/wycheproof``, Apache-2.0).
* Two builds are byte-identical, and ``scripts/build_verifier.py --check`` agrees.
* The pyz runs under ``python -I -S`` with the network refused and no opentine
  importable, and its verdicts equal ``tine verify --offline`` on the compat
  fixtures, the conformance integrity vectors and freshly written v4 runs.
* zstd content is refused with the ``--with-verifier`` hint, and an evidence
  folder exported ``--with-verifier`` verifies with the pyz it carries.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._evidence_export import archival_bytes
from opentine._pyz import _ed25519
from opentine._pyz_build import build_bytes
from opentine.signing import HAS_ED25519, generate_ed25519

ROOT = Path(__file__).resolve().parent.parent
WYCHEPROOF = ROOT / "tests" / "data" / "wycheproof" / "ed25519_test.json"
HMAC_KEY = b"compat-golden-signing-key-000001"
needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="signing needs the crypto extra")

#: RFC 8032 §7.1 TEST 1, 2, 3 and SHA(abc): (public key, message, signature).
RFC8032 = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
        "1cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613"
        "d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760"
        "984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23"
        "a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c6"
        "6431e0303dca179c138ac17ad9bef1177331a704",
    ),
]


@pytest.mark.parametrize(("public", "message", "signature"), RFC8032)
def test_rfc8032_vectors_verify_and_any_flipped_bit_does_not(public, message, signature):
    pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    assert _ed25519.verify(pk, msg, sig)
    assert not _ed25519.verify(pk, msg + b"x", sig)
    assert not _ed25519.verify(pk, msg, sig[:-1] + bytes([sig[-1] ^ 1]))


def test_wycheproof_ed25519_vectors():
    suite = json.loads(WYCHEPROOF.read_text(encoding="utf-8"))
    assert suite["algorithm"] == "EDDSA" and suite["numberOfTests"] == 210
    seen = 0
    for group in suite["testGroups"]:
        public = bytes.fromhex(group["publicKey"]["pk"])
        for case in group["tests"]:
            got = _ed25519.verify(public, bytes.fromhex(case["msg"]), bytes.fromhex(case["sig"]))
            if case["result"] == "invalid":
                assert not got, case["tcId"]
            elif case["result"] == "valid":
                assert got, case["tcId"]
            seen += 1
    assert seen == 210


def test_two_builds_are_byte_identical(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    assert build_bytes() == build_bytes()
    assert build_bytes() != build_bytes(epoch=1767225600 + 86400)
    outs = []
    for name in ("a", "b"):
        done = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_verifier.py"), "--check"]
            + ["--out", str(tmp_path / name)],
            capture_output=True, text=True, timeout=60, check=True,
        )  # fmt: skip
        outs.append(done.stdout.split()[0])
        assert (tmp_path / name / "tine-verify.pyz").read_bytes() == build_bytes()
    assert outs[0] == outs[1]


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tine-verify.pyz").write_bytes(build_bytes())
    return tmp_path


def _run(room: Path, name: str) -> Run:
    run = Run(id=name, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": f"thinking {name} " * 80})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    return run


#: Run inside ``python -I -S``: refuse (and record) the network, prove opentine is
#: not importable, then verify each listed file with the pyz's own code.
_RUNNER = """
import importlib.util, json, socket, sys
attempts = []
def refuse(*a, **k):
    attempts.append(repr(a[:2]))
    raise OSError("network refused by the test")
for name in ("getaddrinfo", "gethostbyname", "create_connection"):
    setattr(socket, name, refuse)
socket.socket.connect = refuse
assert importlib.util.find_spec("opentine") is None, "opentine must not be importable"
sys.path.insert(0, sys.argv[1])
from tine_verify._pyz import _cli
jobs = json.loads(sys.stdin.read())
out = []
for path, kind, key in jobs:
    kw = {"pubkey": _cli.public_key(key)} if kind == "pubkey" else {}
    kw = {"hmac_key": _cli._key_bytes(key)} if kind == "key-file" else kw
    out.append(_cli.verify_file(__import__("pathlib").Path(path), **kw))
print(json.dumps({"reports": out, "attempts": attempts}))
"""


def _pyz_reports(room: Path, jobs: list[tuple[str, str | None, str | None]]) -> list[dict]:
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-c", _RUNNER, str(room / "tine-verify.pyz")],
        input=json.dumps(jobs), capture_output=True, text=True, timeout=300, cwd=room,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout)
    assert result["attempts"] == []
    return result["reports"]


def _reference(capsys, path: str, kind: str | None, key: str | None) -> dict:
    argv = ["verify", path, "--offline", "--json"] + ([f"--{kind}", key] if kind else [])
    try:
        cli.main(argv)
    except SystemExit:
        pass
    return json.loads(capsys.readouterr().out)


def _verdicts(report: dict) -> tuple:
    checks = {c["name"]: (c["outcome"], c["reason"]) for c in report["checks"]}
    return report["verdict"], checks.get("digest"), checks.get("signature")


def _jobs(room: Path) -> list[tuple[str, str | None, str | None]]:
    """Every fixture to compare, zstd ones re-encoded as ``--with-verifier`` would."""
    jobs: list[tuple[str, str | None, str | None]] = []
    (room / "hmac.key").write_bytes(HMAC_KEY)
    fixtures = sorted(p for p in (ROOT / "tests" / "fixtures").rglob("*.tine") if p.is_file())
    for index, source in enumerate(fixtures):
        target = room / "fixtures" / f"{index:03d}-{source.name}"
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(archival_bytes(source.read_bytes()))
        jobs.append((str(target), None, None))
        if "signed" in source.name:
            jobs.append((str(target), "key-file", str(room / "hmac.key")))
    vectors = json.loads((ROOT / "docs/conformance/vectors/35-integrity.json").read_text("utf-8"))
    for case in vectors["cases"]:
        target = room / "vectors" / f"{case['id']}.tine"
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(base64.b64decode(case["input"]["bytes_b64"]))
        jobs.append((str(target), None, None))
    return jobs


def _v4_jobs(room: Path) -> list[tuple[str, str | None, str | None]]:
    plain = _run(room, "plain")
    plain.save(room / "plain.tine")
    jobs: list[tuple[str, str | None, str | None]] = [(str(room / "plain.tine"), None, None)]
    plain.save(room / "hmac.tine", sign_key=HMAC_KEY)
    jobs += [(str(room / "hmac.tine"), k, v) for k, v in ((None, None), ("key-file", "hmac.key"))]
    if HAS_ED25519:
        seed, public = generate_ed25519()
        (room / "ed.pub").write_text(public + "\n", encoding="utf-8")
        _, other = generate_ed25519()
        (room / "other.pub").write_text(other + "\n", encoding="utf-8")
        plain.save(room / "ed.tine", sign_key=seed, sign_algorithm="ed25519")
        for key in ("ed.pub", "other.pub"):
            jobs.append((str(room / "ed.tine"), "pubkey", key))
        jobs.append((str(room / "ed.tine"), "key-file", "hmac.key"))
    from opentine._artifact_io import read_artifact_json

    for name, edit in _TAMPERS.items():
        data = read_artifact_json(room / ("ed.tine" if HAS_ED25519 else "hmac.tine"))
        edit(data)
        (room / f"t-{name}.tine").write_text(json.dumps(data), encoding="utf-8")
        jobs.append((str(room / f"t-{name}.tine"), "pubkey" if HAS_ED25519 else None, "ed.pub"))
    return [(p, k, str(room / v) if v and not Path(v).is_absolute() else v) for p, k, v in jobs]


def _edit_body(data: dict) -> None:
    oid = next(o for o in data["objects"] if o.startswith("event:"))
    data["objects"][oid]["body"]["kind"] = "tampered"


def _orphan(data: dict) -> None:
    data["objects"]["blob:sha256:" + "0" * 64] = {"encoding": "raw", "schema": 1, "type": "blob",
                                                    "data": ""}  # fmt: skip


_TAMPERS = {
    "body": _edit_body,
    "orphan": _orphan,
    "root": lambda d: d.update(root="run:sha256:" + "1" * 64),
    "sig-value": lambda d: d["signatures"][0].update(value="0" * len(d["signatures"][0]["value"])),
    "sig-null": lambda d: d["signatures"][0].update(signer=None),
    "extra-key": lambda d: d.update(extra=1),
}


def test_pyz_verdicts_equal_tine_verify_offline(room, capsys):
    jobs = _jobs(room) + _v4_jobs(room)
    reports = _pyz_reports(room, jobs)
    assert len(reports) == len(jobs) > 150
    mismatched = [
        (job, _verdicts(mine), _verdicts(_reference(capsys, *job)))
        for job, mine in zip(jobs, reports, strict=True)
        if _verdicts(mine) != _verdicts(_reference(capsys, *job))
    ]
    assert mismatched == []
    verdicts = {_verdicts(r)[0] for r in reports}
    assert verdicts == {"pass", "fail"}


def test_pyz_verifies_a_v4_file_isolated_and_offline(room):
    run = _run(room, "solo")
    run.save(room / "solo.tine")
    (room / "solo.tine").write_bytes(archival_bytes((room / "solo.tine").read_bytes()))
    done = subprocess.run(
        [sys.executable, "-I", "-S", "tine-verify.pyz", "solo.tine"],
        capture_output=True, text=True, timeout=60, cwd=room,
    )  # fmt: skip
    report = json.loads(done.stdout)
    assert done.returncode == 0 and report["verdict"] == "pass"
    assert report["checks"][0]["detail"].startswith("root run:sha256:")
    assert _pyz_reports(room, [(str(room / "solo.tine"), None, None)])[0]["ok"]


def test_zstd_is_refused_with_the_reexport_hint(room):
    zstd = next(p for p in (ROOT / "tests/fixtures/compat").rglob("artifact.tine")
                if p.read_bytes()[7:8] == b"\x02")  # fmt: skip
    done = subprocess.run(
        [sys.executable, "-I", "-S", "tine-verify.pyz", str(zstd)],
        capture_output=True, text=True, timeout=60, cwd=room,
    )  # fmt: skip
    report = json.loads(done.stdout)
    assert done.returncode == 1
    assert report["checks"][0]["reason"] == "digest.zstd-unsupported"
    assert "tine evidence export --with-verifier" in report["checks"][0]["detail"]


def test_evidence_export_with_verifier_verifies_with_its_own_pyz(room):
    zstd = next(p for p in (ROOT / "tests/fixtures/compat").rglob("artifact.tine")
                if p.read_bytes()[7:8] == b"\x02")  # fmt: skip
    (room / "old.tine").write_bytes(zstd.read_bytes())
    _run(room, "fresh").save(room / "fresh.tine")
    cli.main(["evidence", "export", "old.tine", "fresh.tine", "--out", "ev", "--with-verifier"])
    pyz = room / "ev" / "tine-verify.pyz"
    assert pyz.read_bytes() == build_bytes()
    assert (room / "ev" / "runs" / "old.tine").read_bytes()[7:8] != b"\x02"
    done = subprocess.run(
        [sys.executable, "-I", "-S", str(pyz), "ev"],
        capture_output=True, text=True, timeout=120, cwd=room,
    )  # fmt: skip
    report = json.loads(done.stdout)
    assert done.returncode == 0, report
    names = {c["name"]: c["outcome"] for c in report["checks"]}
    assert names["manifest"] == names["custody"] == "pass"
    assert len(report["runs"]) == 2
    (room / "ev" / "runs" / "fresh.tine").write_bytes(b"{}")
    done = subprocess.run(
        [sys.executable, "-I", "-S", str(pyz), "ev"],
        capture_output=True, text=True, timeout=120, cwd=room,
    )  # fmt: skip
    assert done.returncode == 1


@needs_ed25519
def test_pure_ed25519_agrees_with_cryptography_on_random_keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    for index in range(8):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes_raw()
        message = bytes([index]) * index
        signature = key.sign(message)
        assert _ed25519.verify(public, message, signature)
        assert not _ed25519.verify(public, message + b"!", signature)


def test_publish_workflow_ships_the_pyz_under_sums_and_provenance():
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "scripts/build_verifier.py --out verifier --check" in text
    assert "opentine.cdx.json tine-verify.pyz > SHA256SUMS" in text
    subjects = text.split("subject-path: |", 1)[1].split("- name:", 1)[0]
    assert "dist/tine-verify.pyz" in subjects
    assert "dist/tine-verify.pyz" in text.split("gh release create", 1)[1]
