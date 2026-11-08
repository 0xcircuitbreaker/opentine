"""0.45.1: ``tine watch``, and the webhook vectors through the pyz and the documented verifiers."""

from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

from opentine import _schemas, cli
from opentine._pyz import _webhook
from opentine._pyz_build import build_bytes
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._http_server import ThreadingWSGIServer, TimeoutRequestHandler
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "docs/conformance/vectors/59-webhook.json").read_text("utf-8"))["cases"]
DOC = (ROOT / "docs" / "EVENTS.md").read_text("utf-8")


def _value(case: dict) -> dict:
    return tagged.decode(case["input"]["value"])


def _plain_vectors(tmp_path: Path) -> str:
    """The vectors with their tagged integers decoded, for the out-of-process runners."""
    path = tmp_path / "webhook-vectors.json"
    cases = [{"input": {"value": _value(case)}} for case in CASES]
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path.as_posix()


def _block(language: str) -> str:
    match = re.search(rf"<!-- verifier:{language} -->\n```\w+\n(.*?)```", DOC, re.S)
    assert match, language
    return match.group(1)


def test_the_documented_verifiers_are_at_most_twenty_lines():
    for language in ("python", "js"):
        lines = [line for line in _block(language).splitlines() if line.strip()]
        body = [line for line in lines if not line.startswith(("import ", "from ", "const crypto"))]
        assert len(body) <= 20, (language, len(body))


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_the_pyz_answers_every_webhook_vector(case):
    assert _webhook.verify_case(_value(case)) == case["output"]


def test_the_built_pyz_carries_the_webhook_verifier(tmp_path):
    (tmp_path / "tine-verify.pyz").write_bytes(build_bytes())
    with zipfile.ZipFile(tmp_path / "tine-verify.pyz") as archive:
        assert "tine_verify/_pyz/_webhook.py" in archive.namelist()
    script = (
        "import json, sys\nsys.path.insert(0, sys.argv[1])\n"
        "from tine_verify._pyz import _webhook\n"
        "cases = json.load(open(sys.argv[2], encoding='utf-8'))['cases']\n"
        "print(json.dumps([_webhook.verify_case(c['input']['value']) for c in cases]))\n"
    )
    vectors = _plain_vectors(tmp_path)
    done = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            script,
            (tmp_path / "tine-verify.pyz").as_posix(),
            vectors,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [case["output"] for case in CASES]


def test_the_documented_python_verifier_runs_against_the_vectors():
    namespace: dict = {}
    exec(compile(_block("python"), "docs/EVENTS.md", "exec"), namespace)  # noqa: S102
    for case in CASES:
        value = _value(case)
        body = base64.b64decode(value["body_b64"])
        try:
            payload = namespace["verify_webhook"](
                body, value["header"], value["keys"], now=value["now"], window=value["window"]
            )
            ok = payload.get("format") == "tine-webhook/1"
        except Exception:  # noqa: BLE001 - any refusal
            ok = False
        assert ok == case["output"]["ok"], case["id"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_documented_js_verifier_runs_against_the_vectors(tmp_path):
    (tmp_path / "verify.cjs").write_text(_block("js"), encoding="utf-8")
    runner = (
        "const { verifyWebhook } = require(process.argv[2]);\n"
        "const cases = JSON.parse(require('fs').readFileSync(process.argv[3], 'utf8')).cases;\n"
        "console.log(JSON.stringify(cases.map((c) => { const v = c.input.value; try {\n"
        "  const body = Buffer.from(v.body_b64, 'base64');\n"
        "  const p = verifyWebhook(body, v.header, v.keys, v.now, v.window);\n"
        "  return p.format === 'tine-webhook/1'; } catch (e) { return false; } })));\n"
    )
    (tmp_path / "run.cjs").write_text(runner, encoding="utf-8")
    vectors = _plain_vectors(tmp_path)
    argv = [
        "node",
        (tmp_path / "run.cjs").as_posix(),
        (tmp_path / "verify.cjs").as_posix(),
        vectors,
    ]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [case["output"]["ok"] for case in CASES]


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def test_watch_tails_a_local_op_log(tmp_path, monkeypatch, capsys):
    from opentine import Run
    from opentine.graph import StepKind
    from opentine.repository import Repo
    from opentine.repository._oplog import operation

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    repo = Repo.init(tmp_path / "repo")
    run = Run(id="r1")
    run.add_step(StepKind.done, {"text": "x"})
    with operation("test commit"):
        repo.put_run(run, ref="heads/main")
    code, out = _tine(capsys, "watch", (tmp_path / "repo").as_posix(), "--once", "--json")
    assert code == 0 and out == ""
    code, out = _tine(
        capsys, "watch", (tmp_path / "repo").as_posix(), "--once", "--from-start", "--json"
    )
    assert code == 0
    lines = [json.loads(line) for line in out.splitlines()]
    assert lines and lines[0]["event"]["kind"] == "op.logged"
    assert lines[0]["event"]["data"]["command"] == "test commit"
    for line in lines:
        assert _schemas.validate_output(line) == []


def test_watch_tails_a_remote_event_stream(tmp_path, monkeypatch, capsys):
    identities = StaticTokenIdentityProvider({"t": Identity("alice", "acme", ("writer",))})
    app = server.reference_app(
        tmp_path / "remote", identities=identities, keys=LocalKeyProvider(b"k" * 32)
    )
    app.stream_seconds = 5.0
    handler = type("_H", (TimeoutRequestHandler,), {"timeout": 10, "header_timeout": 5})
    httpd = make_server(
        "127.0.0.1", 0, app, server_class=ThreadingWSGIServer, handler_class=handler
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    hub = app.service.events

    def publish() -> None:
        time.sleep(0.5)
        hub.ref_moved("other", "heads/x", None, "run:" + "1" * 64, False)
        hub.ref_moved("acme", "heads/main", None, "run:" + "2" * 64, True)

    threading.Thread(target=publish, daemon=True).start()
    monkeypatch.setenv("TINE_REMOTE_TOKEN", "t")
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        code, out = _tine(
            capsys,
            "watch",
            url,
            "--tenant",
            "acme",
            "--max-events",
            "1",
            "--json",
            "--timeout",
            "20",
        )
    finally:
        httpd.shutdown()
    assert code == 0, out
    line = json.loads(out.splitlines()[0])
    assert line["event"]["data"]["name"] == "heads/main" and line["event"]["tenant"] == "acme"
    assert _schemas.validate_output(line) == []
