"""0.49: ``tine publish zenodo`` and ``tine publish hf`` against in-process fake servers.

Offline: every request goes through an ``httpx.MockTransport`` that answers
like the Zenodo deposit API or the Hugging Face Hub (create repo, Git LFS
batch, commit). Both commands refuse unredacted content with the push gate
before any request, never print or log a token, and record what they
published in the op log.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from opentine import _publish_common, _push_gate, cli
from opentine._schemas import validate
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository._oplog import read_ops

TOKEN = "publish-test-token-6f1d2c"
FAKE = "sk-proj-" + "Zq7Xw2Lr9Tb4Nc8Vm1Hs6Jd3Kf5Gp0Ya"
KEY = b"ab" * 32


class FakeServer:
    """Answers like Zenodo or the Hub; keeps every request."""

    def __init__(self, fail: dict[str, int] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.fail = fail or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path, method = request.url.path, request.method
        for suffix, status in self.fail.items():
            if path.endswith(suffix):
                return httpx.Response(status, json={"message": f"echo {request.headers}"})
        if method == "POST" and path == "/api/deposit/depositions":
            links = {
                "bucket": "https://zenodo.test/api/files/b-1",
                "html": "https://zenodo.test/d/7",
            }
            return httpx.Response(201, json={"id": 7, "links": links})
        if method == "PUT" and path.startswith("/api/files/b-1/"):
            return httpx.Response(201, json={"checksum": "md5:00"})
        if method == "PUT" and path == "/api/deposit/depositions/7":
            return httpx.Response(200, json={"id": 7})
        if path.endswith("/actions/publish"):
            links = {"record_html": "https://zenodo.test/records/7"}
            return httpx.Response(202, json={"doi": "10.5072/zenodo.7", "links": links})
        if path == "/api/repos/create":
            return httpx.Response(409, json={})
        if path.endswith("/info/lfs/objects/batch"):
            obj = json.loads(request.content)["objects"][0]
            actions = {
                "upload": {"href": "https://storage.test/up", "header": {"X-Up": "1"}},
                "verify": {"href": "https://hub.test/lfs/verify", "header": {}},
            }
            return httpx.Response(200, json={"objects": [{**obj, "actions": actions}]})
        if path == "/up" or path == "/lfs/verify":
            return httpx.Response(200)
        if "/commit/" in path:
            body = {"commitOid": "c0ffee", "commitUrl": "https://hub.test/datasets/o/d/commit/c0"}
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={})

    def install(self, monkeypatch) -> FakeServer:
        transport = httpx.MockTransport(self)
        monkeypatch.setattr(_publish_common, "client", lambda: httpx.Client(transport=transport))
        return self


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("ZENODO_TOKEN", TOKEN)
    monkeypatch.setenv("HF_TOKEN", TOKEN)
    repo = Repo.init(tmp_path / "s")
    run = Run(id="r", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "hello"})
    repo.put_run(run, ref="heads/main")
    return repo


def _tine(capsys, *argv: str) -> tuple[int, str, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out, err = capsys.readouterr()
    return code, out, err


def _zenodo(store, *extra: str) -> list[str]:
    return [
        "publish",
        "zenodo",
        "heads/main",
        "--creator",
        "Doe, Jane",
        "--api-url",
        "https://zenodo.test/api",
        "--repo",
        str(store.path),
        "--json",
        *extra,
    ]


def _hf(store, key, *extra: str) -> list[str]:
    return [
        "publish",
        "hf",
        "heads/main",
        "--dataset",
        "o/d",
        "--key-file",
        str(key),
        "--api-url",
        "https://hub.test",
        "--repo",
        str(store.path),
        "--json",
        *extra,
    ]


def _notes(store) -> list[str]:
    return [op["note"] for op in read_ops(store.path) if op.get("note")]


def test_zenodo_deposits_a_draft_and_logs_it(store, monkeypatch, capsys):
    server = FakeServer().install(monkeypatch)
    code, out, err = _tine(capsys, *_zenodo(store))
    assert code == 0, err
    body = json.loads(out)
    assert validate(body, "tine-cli-publish-1")[1] == []
    assert body["published"]["state"] == "draft" and body["published"]["doi"] is None
    assert [r.method for r in server.requests] == ["POST", "PUT", "PUT"]
    assert all(r.headers["authorization"] == f"Bearer {TOKEN}" for r in server.requests)
    meta = json.loads(server.requests[-1].content)["metadata"]
    assert meta["creators"] == [{"name": "Doe, Jane"}] and meta["upload_type"] == "dataset"
    assert server.requests[1].content.startswith(b"TINE")  # the bundle bytes themselves
    notes = _notes(store)
    assert notes and "publish zenodo: deposition 7 (draft)" in notes[-1]
    assert body["bundle"]["digest"] in notes[-1]
    assert TOKEN not in out + err + json.dumps(read_ops(store.path))


def test_zenodo_publish_mints_a_doi_and_sandbox_is_a_flag(store, monkeypatch, capsys):
    server = FakeServer().install(monkeypatch)
    code, out, _ = _tine(capsys, *_zenodo(store, "--publish"))
    assert code == 0
    assert json.loads(out)["published"]["doi"] == "10.5072/zenodo.7"
    assert server.requests[-1].url.path.endswith("/actions/publish")
    argv = [a for a in _zenodo(store, "--sandbox", "--dry-run") if a != "https://zenodo.test/api"]
    argv.remove("--api-url")
    code, out, _ = _tine(capsys, *argv)
    assert json.loads(out)["api"] == "https://sandbox.zenodo.org/api"


def test_dry_run_needs_no_token_and_sends_nothing(store, monkeypatch, capsys):
    monkeypatch.delenv("ZENODO_TOKEN")
    server = FakeServer().install(monkeypatch)
    code, out, _ = _tine(capsys, *_zenodo(store, "--dry-run"))
    assert code == 0 and server.requests == []
    body = json.loads(out)
    assert validate(body, "tine-cli-publish-1")[1] == []
    assert body["plan"][0] == {"method": "POST", "path": "/deposit/depositions"}
    assert _notes(store) == []


def test_unredacted_content_is_refused_before_any_request(store, monkeypatch, capsys, tmp_path):
    server = FakeServer().install(monkeypatch)
    blob = store.put("blob", FAKE.encode(), redact=False)
    original = _publish_common.bundle_objects
    monkeypatch.setattr(_publish_common, "bundle_objects", lambda *a: original(*a) | {blob})
    code, _, err = _tine(capsys, *_zenodo(store))
    assert code != 0 and "push refused" in err and server.requests == []
    code, out, _ = _tine(capsys, *_zenodo(store, "--allow-unredacted", "reviewed"))
    assert code == 0 and any("allow-unredacted: reviewed" in n for n in _notes(store))
    crate = tmp_path / "crate.json"
    crate.write_text(json.dumps({"token": FAKE}), encoding="utf-8")
    monkeypatch.setattr(_publish_common, "bundle_objects", original)
    server.requests.clear()
    code, _, err = _tine(capsys, *_zenodo(store, "--attach", str(crate)))
    assert code != 0 and "crate.json fails the redaction scan" in err and server.requests == []


def test_a_failure_names_the_status_never_the_token(store, monkeypatch, capsys):
    FakeServer(fail={"/deposit/depositions": 403}).install(monkeypatch)
    code, out, err = _tine(capsys, *_zenodo(store))
    assert code != 0 and "HTTP 403" in err and TOKEN not in out + err
    monkeypatch.delenv("ZENODO_TOKEN")
    code, _, err = _tine(capsys, *_zenodo(store))
    assert code != 0 and "ZENODO_TOKEN" in err


def test_a_bucket_off_the_api_host_never_gets_the_token(store, monkeypatch, capsys):
    server = FakeServer()

    def moved(request):
        if request.url.path == "/api/deposit/depositions" and request.method == "POST":
            server.requests.append(request)
            return httpx.Response(201, json={"id": 7, "links": {"bucket": "https://evil.test/b"}})
        return server(request)

    transport = httpx.MockTransport(moved)
    monkeypatch.setattr(_publish_common, "client", lambda: httpx.Client(transport=transport))
    code, _, err = _tine(capsys, *_zenodo(store))
    assert code != 0 and "off its own host" in err
    assert all(r.url.host != "evil.test" for r in server.requests)


def test_hf_uploads_the_redacted_signed_copy_with_a_card(store, monkeypatch, capsys, tmp_path):
    key = tmp_path / "k"
    key.write_text(KEY.decode(), encoding="utf-8")
    server = FakeServer().install(monkeypatch)
    code, out, err = _tine(capsys, *_hf(store, key, "--create"))
    assert code == 0, err
    body = json.loads(out)
    assert validate(body, "tine-cli-publish-1")[1] == []
    assert body["published"]["commit"] == "c0ffee" and body["dataset"] == "o/d"
    upload = next(r for r in server.requests if r.url.host == "storage.test")
    assert "authorization" not in upload.headers and upload.headers["x-up"] == "1"
    commit = next(r for r in server.requests if "/commit/" in r.url.path)
    lines = [json.loads(line) for line in commit.content.splitlines()]
    assert [line["key"] for line in lines] == ["header", "lfsFile", "file"]
    readme = base64.b64decode(lines[2]["value"]["content"]).decode("utf-8")
    assert "- agent-traces" in readme and body["bundle"]["digest"] in readme
    notes = _notes(store)
    assert notes and notes[-1].startswith("publish hf: dataset o/d@main commit c0ffee")
    assert TOKEN not in out + err + json.dumps(read_ops(store.path))


def test_hf_needs_a_key_and_refuses_unredacted_copies(store, monkeypatch, capsys, tmp_path):
    server = FakeServer().install(monkeypatch)
    argv = [a for a in _hf(store, "x") if a not in ("--key-file", "x")]
    code, _, err = _tine(capsys, *argv)
    assert code != 0 and "--key-file" in err and server.requests == []
    key = tmp_path / "k"
    key.write_text(KEY.decode(), encoding="utf-8")
    monkeypatch.setattr(_push_gate, "scan", lambda *_a: [{"oid": "blob:x", "kind": "blob"}])
    code, _, err = _tine(capsys, *_hf(store, key))
    assert code != 0 and "no override" in err and server.requests == []


def test_hf_rejects_a_dataset_id_that_climbs_the_path(store, monkeypatch, capsys, tmp_path):
    server = FakeServer().install(monkeypatch)
    argv = _hf(store, tmp_path / "k")
    argv[argv.index("o/d")] = "../x"
    code, _, err = _tine(capsys, *argv)
    assert code != 0 and "OWNER/NAME" in err and server.requests == []
