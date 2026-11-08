"""0.45.1: ``tine ui`` re-checks a run in the browser with the bundled TS verifier.

The server hands the worker the artifact bytes (only when the redaction scan of
the decoded artifact is clean) and ``tine-verifier.js``; the worker computes
integrity and signature states itself. The Node tests import the committed
browser assets directly, so they check what ships, not a fresh build.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from opentine import Run, cli
from opentine._codec import wrap
from opentine._signing_keys import generate_ed25519
from opentine._ui_server import Catalog, make_server
from opentine.core import RunStatus, StepKind

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "opentine" / "data" / "ui"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")
pytestmark = pytest.mark.filterwarnings("ignore::opentine._key_store.PlaintextKeyWarning")


def _signed(room: Path) -> Path:
    run = Run(user_prompt="hello", model_info="model-a")
    run.add_step(StepKind.model, inputs={"messages": [{"role": "user", "content": "hi"}]})
    run.status = RunStatus.completed
    path = room / "run.tine"
    run.save(path)
    private, _public = generate_ed25519()
    (room / "k").write_text(private, encoding="ascii")
    (room / "k").chmod(0o600)
    cli.main(["sign", str(path), "--algorithm", "ed25519", "--ed25519-key-file",
              str(room / "k"), "--save", str(path), "--overwrite"])  # fmt: skip
    return path


def _serve(paths: list[Path]):
    server = make_server(Catalog(paths))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _get(url: str) -> tuple[int, bytes, dict]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=10) as res:
            return res.status, res.read(), dict(res.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_the_server_hands_out_the_verifier_and_clean_artifact_bytes(tmp_path):
    path = _signed(tmp_path)
    run = Run.load(path)
    server, base = _serve([path])
    try:
        status, body, headers = _get(base + "/tine-verifier.js")
        assert status == 200 and headers["Content-Type"].startswith("text/javascript")
        assert body == (UI / "tine-verifier.js").read_bytes()
        status, body, headers = _get(base + f"/api/run/{run.id}/artifact")
        assert status == 200 and body == path.read_bytes()
        assert headers["Content-Type"] == "application/octet-stream"
        assert _get(base + "/api/run/nope/artifact")[0] == 404
    finally:
        server.shutdown()
        server.server_close()


def test_an_artifact_the_redaction_scan_flags_is_withheld(tmp_path):
    path = _signed(tmp_path)
    run = Run.load(path)
    secret = "sk-ant-api03-" + "Q" * 80
    server, base = _serve([path])
    try:
        assert _get(base + "/api/runs")[0] == 200  # loaded; the bytes then change on disk
        text = path.read_text("utf-8").replace('"hello"', json.dumps(secret), 1)
        path.write_text(text, encoding="utf-8")
        status, body, _ = _get(base + f"/api/run/{run.id}/artifact")
        assert status == 403 and secret.encode() not in body
    finally:
        server.shutdown()
        server.server_close()


def test_a_non_utf8_artifact_is_withheld_not_served_unscanned(tmp_path):
    path = _signed(tmp_path)
    run = Run.load(path)
    secret = b"sk-ant-api03-" + b"Q" * 80
    server, base = _serve([path])
    try:
        assert _get(base + "/api/runs")[0] == 200
        path.write_bytes(path.read_bytes().replace(b'"hello"', b'"\xff' + secret + b'"', 1))
        status, body, _ = _get(base + f"/api/run/{run.id}/artifact")
        assert status == 403 and secret not in body
    finally:
        server.shutdown()
        server.server_close()


def _node(script: str, *args: str) -> dict:
    done = subprocess.run([NODE, "--input-type=module", "-e", script, *args],
                          capture_output=True, text=True, timeout=120, cwd=UI)  # fmt: skip
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


CHECK = """
import { readFileSync } from "node:fs";
import { verifyArtifact } from "./tine-verifier.js";
import { badge, browserStates } from "./verify-browser.js";
const report = await verifyArtifact(new Uint8Array(readFileSync(process.argv[1])));
const mine = browserStates(report);
const b = badge({ integrity: "verified", signature: "unpinned", overall: "partial" }, mine);
console.log(JSON.stringify({ report, mine, badge: b }));
"""


@needs_node
def test_the_bundle_computes_real_verdicts_in_a_js_runtime(tmp_path):
    path = _signed(tmp_path)
    found = _node(CHECK, path.as_posix())
    assert found["report"]["integrity"]["ok"] and found["report"]["ok"]
    assert found["report"]["signature"]["state"] == "verified-tofu"
    assert found["mine"]["integrity"] == "verified" and found["mine"]["signature"] == "unpinned"
    assert found["badge"]["state"] == "partial"
    assert "re-checked in this browser" in found["badge"]["label"]
    data = json.loads(path.read_text("utf-8"))
    data["root"] = "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    found = _node(CHECK, path.as_posix())
    assert found["mine"]["integrity"] == "failed" and found["badge"]["state"] == "failed"


@needs_node
def test_the_bundle_inflates_a_zlib_wrapped_artifact(tmp_path):
    path = _signed(tmp_path)
    wrapped = wrap(path.read_bytes(), "zlib", force=True)
    assert wrapped is not None and wrapped[7] == 1
    path.write_bytes(wrapped)
    found = _node(CHECK, path.as_posix())
    assert found["mine"]["integrity"] == "verified", found["report"]
    path.write_bytes(wrapped[:-4])  # a truncated frame
    found = _node(CHECK, path.as_posix())
    assert found["mine"]["integrity"] == "failed"


@needs_node
def test_a_signature_that_does_not_hold_reads_failed(tmp_path):
    path = _signed(tmp_path)
    data = json.loads(path.read_text("utf-8"))
    blocks = json.dumps(data).count('"value"')
    assert blocks, "the signed artifact carries a signature value"
    text = path.read_text("utf-8")
    start = text.index('"value"')
    at = text.index('"', start + len('"value"') + 1) + 1
    flipped = text[:at] + ("0" if text[at] != "0" else "1") + text[at + 1 :]
    path.write_text(flipped, encoding="utf-8")
    found = _node(CHECK, path.as_posix())
    assert found["mine"]["signature"] == "failed" and found["badge"]["state"] == "failed"


@needs_node
def test_a_check_that_cannot_run_reads_unchecked_and_says_why():
    script = """
import { badge, browserStates } from "./verify-browser.js";
const b = badge({ overall: "verified" }, browserStates(null, "artifact withheld"));
console.log(JSON.stringify(b));
"""
    found = _node(script)
    assert found["state"] == "verified" and found["detail"] == "artifact withheld"
    assert [row[1] for row in found["rows"][2:]] == ["unchecked", "unchecked"]


@pytest.mark.skipif(
    NODE is None
    or not (ROOT / "ts" / "run-viewer" / "node_modules" / "esbuild").is_dir()
    or not (ROOT / "ts" / "verifier" / "node_modules" / "@noble").is_dir(),
    reason="run-viewer and verifier devDependencies not installed",
)
def test_the_committed_verifier_bundle_is_reproducible(tmp_path):
    out = tmp_path / "tine-verifier.js"
    script = ROOT / "ts" / "run-viewer" / "build-verifier.mjs"
    subprocess.run([NODE, script.as_posix(), out.as_posix()], check=True, timeout=300)
    assert out.read_bytes() == (UI / "tine-verifier.js").read_bytes()
