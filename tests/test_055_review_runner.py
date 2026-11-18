"""0.55: the review runner (``tine review runner``), hosted and self-hosted.

A deterministic reviewer fleet and ``.tine/evals.toml`` run on one push in
``hosted`` and in ``self-hosted`` mode; the signed findings are byte-identical,
the exported decisions verify with ``tine-verify.pyz`` (always offline), the
runner key gates a merge only while the user's gate policy names it, the
sandbox refuses egress outside the configured model endpoints and every step's
evidence carries the sandbox policy digest.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _merge_gates, _review_runner, _runner_sandbox, _schemas, cli
from opentine._pyz_build import build_bytes
from opentine.repository import Repo

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
RUNNER, USER = "5a" * 32, "ab" * 32
RUN = "run:sha256:" + "7" * 64
AT = "2026-11-01T12:00:00Z"
HARNESS = """\
import json, os
context = open(os.environ["OPENTINE_REVIEW_CONTEXT"], encoding="utf-8").read()
rows = [{"severity": "low", "message": "reviewed " + os.environ["OPENTINE_REVIEW_ID"]}]
if "TODO" in context:
    rows.append({"severity": "medium", "message": "a TODO landed", "path": "app.py", "line": 2})
with open(os.environ["OPENTINE_REVIEW_FINDINGS"], "w", encoding="utf-8") as out:
    out.write("".join(json.dumps(row) + "\\n" for row in rows))
"""


def _key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))


def _git(root: Path, *argv: str) -> str:
    done = subprocess.run(["git", "-C", root.as_posix(), *argv], check=True, capture_output=True)
    return done.stdout.decode().strip()


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out = capsys.readouterr().out
    document = json.loads(out) if out.strip().startswith("{") else {}
    if code == 0 and document:
        assert _schemas.validate_output(document) == [], document
    return code, document


def _checkout(base: Path, name: str, monkeypatch) -> tuple[Path, dict]:
    """One fixture repository with a pushed change, its Review naming the runner."""
    for var, value in (("GIT_AUTHOR_NAME", "T"), ("GIT_AUTHOR_EMAIL", "t@example.invalid"),
                       ("GIT_COMMITTER_NAME", "T"), ("GIT_COMMITTER_EMAIL", "t@example.invalid"),
                       ("GIT_AUTHOR_DATE", AT), ("GIT_COMMITTER_DATE", AT)):  # fmt: skip
        monkeypatch.setenv(var, value)
    root = base / name
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    (root / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "-q", "-m", "init")
    before = _git(root, "rev-parse", "HEAD")
    (root / "app.py").write_text("def main():\n    # TODO\n    return 2\n", encoding="utf-8")
    _git(root, "commit", "-q", "-am", "change")
    Repo.init(root)
    (root / "evals").mkdir()
    item = {"id": "q", "input": "1", "expected": "1", "output": "1", "run": RUN}
    (root / "evals" / "smoke.jsonl").write_text(json.dumps(item) + "\n", encoding="utf-8")
    (root / ".tine" / "evals.toml").write_text(
        '[[eval]]\nname = "smoke"\ndataset = "evals/smoke.jsonl"\nscorer = "exact"\n', "utf-8"
    )
    (root / ".tine" / "runner.toml").write_text(
        '[runner]\nevals = ".tine/evals.toml"\n\n[[model]]\nname = "m"\n'
        'endpoint = "https://models.example.invalid/v1"\ncredential_env = "RUNNER_MODEL_KEY"\n',
        "utf-8")  # fmt: skip
    reviewers = base / f"{name}-fleet"
    reviewers.mkdir()
    (reviewers / "harness.py").write_text(HARNESS, encoding="utf-8")
    argv = json.dumps([sys.executable, (reviewers / "harness.py").as_posix()])
    (reviewers / "fleet.toml").write_text(
        f'[fleet]\nname = "reviewers"\n\n[[agents]]\nname = "det"\nargv = {argv}\ncount = 2\n',
        encoding="utf-8")  # fmt: skip
    event = {"source": "mirror-sync", "ref": "heads/main", "before": before,
             "after": _git(root, "rev-parse", "HEAD"), "at": AT, "run": RUN}  # fmt: skip
    (base / f"{name}.event.json").write_text(json.dumps(event), encoding="utf-8")
    return root, event


@pytest.fixture
def keys(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    monkeypatch.setenv("RUNNER_MODEL_KEY", "sk-test-never-in-a-report")
    (tmp_path / "runner.key").write_text(RUNNER, encoding="utf-8")
    (tmp_path / "user.key").write_text(USER, encoding="utf-8")
    return tmp_path


def _run(capsys, base: Path, name: str, mode: str, monkeypatch) -> tuple[Path, dict]:
    root, _ = _checkout(base, name, monkeypatch)
    runner_hex = _key(RUNNER).public_key().public_bytes_raw().hex()
    code, out = _tine(capsys, "review", "create", "push", "--title", "Push", "--reviewer",
                      runner_hex, "--ed25519-key-file", (base / "user.key").as_posix(),
                      "--repo", root.as_posix(), "--json")  # fmt: skip
    assert code == 0, out
    code, out = _tine(capsys, "review", "runner", "push", "--fleet",
                      (base / f"{name}-fleet" / "fleet.toml").as_posix(), "--trust",
                      "--event", (base / f"{name}.event.json").as_posix(), "--hosting", mode,
                      "--out", (base / f"{name}-out").as_posix(), "--ed25519-key-file",
                      (base / "runner.key").as_posix(), "--repo", root.as_posix(),
                      "--json")  # fmt: skip
    assert code == 0, out
    return base / f"{name}-out", out["runner"]


def test_hosted_and_self_hosted_sign_byte_identical_findings(keys, capsys, monkeypatch):
    hosted, report = _run(capsys, keys, "hosted", "hosted", monkeypatch)
    selfh, other = _run(capsys, keys, "self", "self-hosted", monkeypatch)
    assert (hosted / "findings.json").read_bytes() == (selfh / "findings.json").read_bytes()
    assert (hosted / "evals" / "smoke" / "verdicts.jsonl").read_bytes() == (
        selfh / "evals" / "smoke" / "verdicts.jsonl").read_bytes()  # fmt: skip
    assert report["vsa"] == other["vsa"]
    assert len(report["review"]["findings"]) == 4
    assert {r["state"] for r in report["review"]["findings"]} == {"verified"}
    assert (report["mode"], other["mode"]) == ("hosted", "self-hosted")
    digest = _runner_sandbox.digest(report["sandbox"])
    assert report["sandbox"]["egress"] == ["models.example.invalid:443"]
    assert [s["evidence"]["sandbox_policy"] for s in report["steps"]] == [digest] * 3
    assert report["identity"]["label"] == "review runner"
    assert report["identity"]["trusted_by_default"] is False
    assert report["credentials"] == {"RUNNER_MODEL_KEY": True}
    assert "sk-test" not in (hosted / "report.json").read_text("utf-8")
    assert report["cost"]["total"] == "0" and report["evals"]["ok"] is True


def test_exported_runner_decisions_verify_offline(keys, capsys, monkeypatch):
    out, _ = _run(capsys, keys, "w", "hosted", monkeypatch)
    pyz = keys / "tine-verify.pyz"
    pyz.write_bytes(build_bytes())
    pub = keys / "runner.pub"
    pub.write_text(_key(RUNNER).public_key().public_bytes_raw().hex(), encoding="utf-8")
    for target in (out / "findings.json", out / "evals" / "smoke"):
        done = subprocess.run([sys.executable, "-I", pyz.as_posix(), target.as_posix(),
                               "--pubkey", pub.as_posix()], capture_output=True, text=True,
                              timeout=300)  # fmt: skip
        assert done.returncode == 0, done.stdout + done.stderr
        assert json.loads(done.stdout)["verdict"] == "pass"


def test_removing_the_runner_key_from_trust_flips_the_gate(keys, capsys, monkeypatch):
    out, report = _run(capsys, keys, "w", "hosted", monkeypatch)
    lines = (out / "evals" / "smoke" / "verdicts.jsonl").read_text("utf-8").splitlines()
    verdicts = [json.loads(line) for line in lines]
    evidence = {"vsa": [report["vsa"]], "evals": verdicts}
    raw = _key(RUNNER).public_key().public_bytes_raw()
    trusted = _review_runner.gate_policy([raw], levels=("OPENTINE_REVIEWED",))
    assert _merge_gates.evaluate(trusted, evidence, RUN, "heads/main")["ok"] is True
    untrusted = _review_runner.gate_policy([])
    result = _merge_gates.evaluate(untrusted, evidence, RUN, "heads/main")
    assert result["ok"] is False and result["gates"] == []
    other = _key(USER).public_key().public_bytes_raw()
    assert _merge_gates.evaluate(_review_runner.gate_policy([other]), evidence, RUN,
                                 "heads/main")["ok"] is False  # fmt: skip


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args: object) -> None:
        pass


def test_the_sandbox_refuses_hosts_outside_the_model_endpoints():
    servers = [HTTPServer(("127.0.0.1", 0), _Ok) for _ in range(2)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    allowed, blocked = (s.server_address[1] for s in servers)
    try:
        policy = _runner_sandbox.policy([f"http://127.0.0.1:{allowed}/v1"], [])
        with _runner_sandbox.EgressGuard(policy):
            with urllib.request.urlopen(f"http://127.0.0.1:{allowed}/", timeout=30) as reply:
                assert reply.read() == b"ok"
            with pytest.raises(_runner_sandbox.EgressRefused):
                socket.create_connection(("127.0.0.1", blocked), timeout=30)
            with pytest.raises(_runner_sandbox.EgressRefused):
                socket.getaddrinfo("example.com", 443)
        socket.create_connection(("127.0.0.1", blocked), timeout=30).close()  # guard lifted
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def test_the_runner_config_keeps_credentials_out_and_checks_triggers(tmp_path):
    bad = tmp_path / "runner.toml"
    bad.write_text('[[model]]\nendpoint = "https://m.example/v1"\napi_key = "sk"\n', "utf-8")
    with pytest.raises(ValueError, match="credentials stay in the environment"):
        _review_runner.load_config(bad)
    bad.write_text('[[model]]\nendpoint = "http://m.example/v1"\n', "utf-8")
    with pytest.raises(ValueError, match="https"):
        _review_runner.load_config(bad)
    with pytest.raises(ValueError):
        _review_runner.check_trigger({"source": "cron", "ref": "heads/main", "at": AT})


def test_the_runner_identity_is_published_and_rotatable(keys, capsys):
    old = keys / "old.pub"
    old.write_text(_key(USER).public_key().public_bytes_raw().hex(), encoding="utf-8")
    code, out = _tine(capsys, "review", "runner-identity", "--ed25519-key-file",
                      (keys / "runner.key").as_posix(), "--previous-pubkey", old.as_posix(),
                      "--json")  # fmt: skip
    assert code == 0, out
    found = out["identity"]
    assert found["label"] == "review runner" and found["trusted_by_default"] is False
    assert found["rotated_from"] == [_review_runner.identity(_key(USER))["fingerprint"]]


def test_the_sandbox_refuses_udp_datagrams_and_triggers_drop_extra_fields():
    policy = _runner_sandbox.policy(["http://127.0.0.1:9/v1"], [])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        with _runner_sandbox.EgressGuard(policy):
            with pytest.raises(_runner_sandbox.EgressRefused):
                udp.sendto(b"q", ("127.0.0.2", 53))
    event = {"source": "webhook", "ref": "heads/main", "at": AT, "token": "secret"}
    assert "token" not in _review_runner.check_trigger(event)
