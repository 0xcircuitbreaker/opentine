"""0.77: the loopback ingest endpoint and ``tine ingest packs``."""

from __future__ import annotations

import http.client
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _ingest_http, _ingest_policy, _ingest_verify, _schemas, cli
from opentine._signing_pins import key_fingerprint
from opentine.kernel import ObjectEnvelope
from opentine.remote import LocalKeyProvider
from opentine.remote._pack_blobs import FilesystemPackBlobs
from opentine.remote._packed_store import PackedObjectStore
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
POLICY = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
RUNNER = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)


@pytest.fixture
def repo(tmp_path):
    repo = Repo.init(tmp_path / "r")
    fpr = key_fingerprint(POLICY.public_key().public_bytes_raw())
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\npolicy = ["{fpr}"]\n'.encode()
    )
    pin_roles(repo.path)
    doc = _ingest_policy.build("ep", capture=[], drop=[], rate=0.5, seed="cd" * 32,
                               issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    _ingest_policy.record(repo, doc, POLICY)
    return repo


def _post(port: int, body: bytes) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)  # a hang guard only
    try:
        conn.request("POST", _ingest_http.ROUTE, body, {"Content-Type": "application/x-ndjson"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def test_concurrent_posts_make_one_unforked_chain(repo):
    server = _ingest_http.start(repo, "ep", RUNNER, clock_ms=lambda: 1_800_000_000_000)
    port = server.server_address[1]
    results: list[tuple[int, dict]] = []
    go = threading.Event()

    def worker(n: int) -> None:
        go.wait()
        body = b"".join(json.dumps({"kind": "episode", "w": n, "j": j}).encode() + b"\n"
                        for j in range(25))  # fmt: skip
        results.append(_post(port, body))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    go.set()
    for thread in threads:
        thread.join()
    try:
        assert all(status == 200 for status, _ in results)
        assert sorted(body["seq"] for _, body in results) == list(range(6))
        status, refused = _post(port, b"not json\n")
        assert status == 400 and "error" in refused
        report = _ingest_verify.verify(repo, "ep")
        assert report["ok"], report["findings"]
        assert report["batches"] == 6 and report["received"] == 150
    finally:
        server.stop()


def test_body_limit_and_loopback_only(repo):
    server = _ingest_http.start(repo, "ep", RUNNER, max_bytes=16)
    try:
        status, body = _post(server.server_address[1], b"x" * 64)
        assert status == 413
    finally:
        server.stop()
    with pytest.raises(ValueError, match="loopback"):
        _ingest_http.IngestServer(("0.0.0.0", 0), repo, "ep", RUNNER, lambda: 0, 16)


def test_cli_packs_reads_a_pack_store(tmp_path, monkeypatch, capsys):
    keys = LocalKeyProvider(b"k" * 32)
    store = PackedObjectStore(FilesystemPackBlobs(tmp_path / "p"), keys)
    env = ObjectEnvelope.create("blob", b"payload")
    store.put_many("acme", [(env.oid, env.encode())])
    monkeypatch.setenv("TINE_REMOTE_PACK_STORE", (tmp_path / "p").as_uri())
    monkeypatch.setenv("TINE_KMS_KEY", (b"k" * 32).hex())
    monkeypatch.setattr(LocalKeyProvider, "from_env", classmethod(lambda cls: keys))
    try:
        cli.main(["ingest", "packs", "--state", (tmp_path / "s").as_posix(), "--tenant", "acme",
                  "--json"])  # fmt: skip
    except SystemExit as exc:
        assert not exc.code
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    assert body["packs"] == [{"tenant": "acme", "packs": 1, "objects": 1, "bad": []}]
