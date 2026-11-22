"""0.77 acceptance: live tail, batched ingest in the query index and the
oversight queue, and packs on object storage read by push, pull, fsck and gc.

* ``tine log -f`` and the ``tail`` SSE route follow runs stored by the normal
  recorder, one verify status per event;
* ingest policies and batches are ``tine query`` rows with a per-row verify;
  a gap or a batch signed by an optimizer key opens an ``ingest`` item in the
  oversight queue;
* a push to a ``TINE_REMOTE_PACK_STORE`` tenant lands as a pack that pull,
  fsck and the purge (gc) read through.
"""

from __future__ import annotations

import json

import pytest

from opentine import (
    Run,
    StepKind,
    _ingest_batch,
    _ingest_holds,
    _oversight_policy,
    _oversight_queue,
    _schemas,
    cli,
)
from opentine._ingest_policy import anchor_id
from opentine.remote import LocalKeyProvider
from opentine.remote._admin import RemoteAdmin
from opentine.remote._packed_store import PackedObjectStore
from opentine.repository import Repo
from opentine.repository.pack import install_pack
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_077_ingest import T0, _events, _fpr, _key, _policy
from tests.test_077_ingest import repo as repo  # noqa: F401 - the pinned-roles fixture
from tests.test_077_tail_sse import _app, _frames, _get, _push

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _tine(capsys, *argv: str) -> tuple[int, dict | list]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    try:
        body = json.loads(out)
    except ValueError:  # JSON Lines: one document per line
        return code, [json.loads(line) for line in out.splitlines() if line.strip()]
    if "error" not in body:
        assert _schemas.validate_output(body) == [], body
    return code, body


def test_log_f_and_sse_follow_recorded_runs_with_a_status_per_event(tmp_path, capsys):
    local = Repo.init(tmp_path / "r")
    run = Run(id="live0001")
    for index in range(3):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    local.put_run(run, ref="heads/main")
    code, rows = _tine(capsys, "log", "-f", "main", "--repo", str(local.path), "--json",
                       "--lines", "3", "--max-events", "3")  # fmt: skip
    assert all(_schemas.validate_output(line) == [] for line in rows)
    rows = [line["row"] for line in rows]
    assert code == 0 and [r["index"] for r in rows] == [0, 1, 2]
    assert {r["status"] for r in rows} == {"verified"}
    app = _app(tmp_path / "srv")
    _push(app, tmp_path, 2)
    _, _, body = _get(app, "lines=2")
    streamed = [json.loads(f["data"]) for f in _frames(body)]
    assert [r["status"] for r in streamed] == ["verified", "verified"]


def test_ingest_is_queryable_and_violations_reach_the_oversight_queue(repo, capsys):
    policy = _policy(repo, rate=0.5)
    heads = [_ingest_batch.append(repo, "rl", _events(50, 50 * i), _key("runner"),
                                  at_ms=T0 + i)["id"] for i in range(3)]  # fmt: skip
    root = str(repo.path)
    code, out = _tine(capsys, "query", "SELECT oid, seq, received, signed FROM ingest_batches"
                      " ORDER BY seq", "--verify", "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    assert [r["oid"] for r in out["rows"]] == heads
    assert [r["received"] for r in out["rows"]] == [50, 50, 50]
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified"] * 3
    code, out = _tine(capsys, "query", "SELECT oid, stream, rate FROM ingest_policies",
                      "--verify", "--repo", root, "--json")  # fmt: skip
    assert code == 0 and out["rows"] == [{"oid": policy, "stream": "rl", "rate": 0.5}]
    assert out["verification"]["rows"][0]["status"] == "verified"
    _pin_oversight(repo)
    assert not [i for i in _oversight_queue.queue(repo)["items"] if i["source"] == "ingest"]

    # A loop holding only its optimizer key skips two batches and moves the held head.
    prior = _ingest_holds.read(repo, heads[-1], _ingest_batch.CONVENTION)["claim"]
    forged = {**prior, "seq": prior["seq"] + 3, "previous": heads[-1], "events": "",
              "first_index": prior["next_index"] + 100, "next_index": prior["next_index"] + 100,
              "received": 0, "captured": 0, "dropped": 0,
              "dropped_by": {"kind": 0, "rate": 0}}  # fmt: skip
    bad = _ingest_holds.write(repo, anchor_id("rl"), forged, _key("optimizer"),
                              previous=heads[-1], signed_at=prior["at"])  # fmt: skip
    _ingest_holds.move_head(repo, "rl", heads[-1], bad)
    items = [i for i in _oversight_queue.queue(repo)["items"] if i["source"] == "ingest"]
    assert [i["item"] for i in items] == [f"ingest:{bad}"]
    assert items[0]["state"] == "pending" and items[0]["tiers"][0]["tier"] == "high"
    code, body = _tine(capsys, "oversight", "queue", "--repo", root, "--json")
    assert f"ingest:{bad}" in {row["item"] for row in body["items"]}
    code, out = _tine(capsys, "query", "SELECT oid, seq FROM ingest_batches WHERE oid = '"
                      + bad + "'", "--verify", "--refresh", "--repo", root, "--json")  # fmt: skip
    check = out["verification"]["rows"][0]
    assert check["status"] == "unverified" and check["signer"] == _fpr("optimizer")
    code, report = _tine(capsys, "ingest", "verify", "rl", "--repo", root, "--json")
    found = {f["code"] for f in report["report"]["findings"] if f["batch"] == bad}
    assert {"ingest.chain-order", "ingest.batch-optimizer-key"} <= found and code == 1


def _pin_oversight(repo) -> None:
    text = (f'version = 1\n[tiers.high]\nk = 1\napprovers = ["{_fpr("runner")}"]\n'
            '[[route]]\nsource = "ingest"\ntier = "high"\n').encode()  # fmt: skip
    (repo.path / "oversight.toml").write_bytes(text)
    doc = _oversight_policy.sign(_key("policy"), text, "2027-01-15T08:00:00Z")
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))


def test_object_store_packs_serve_push_pull_fsck_and_gc(tmp_path, monkeypatch):
    monkeypatch.setenv("TINE_REMOTE_PACK_STORE", (tmp_path / "bucket").resolve().as_uri())
    monkeypatch.delenv("TINE_REMOTE_OBJECT_STORE", raising=False)
    app = _app(tmp_path / "srv")
    service = app.service
    assert isinstance(service.objects, PackedObjectStore)
    run = _push(app, tmp_path, 3)  # push: one pack for the whole upload
    run_id = service.index.list_refs("acme")["heads/main"]
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    clone = Repo.init(tmp_path / "clone")
    install_pack(clone, service.fetch_pack(writer, "acme", [run_id], []))  # pull
    assert len(clone.get(run_id).payload()["events"]) == len(run.steps)
    assert service.objects.fsck("acme")["bad"] == []
    loose = Repo.init(tmp_path / "loose")
    stray = loose.put("blob", b"an object no ref reaches", redact=False)
    service.install_pack(writer, "acme", loose.pack())
    admin = RemoteAdmin(service.objects, service.index)
    kept = admin.purge("acme")  # gc: object storage keeps no age, so the grace defers
    assert kept.removed == () and stray in service.objects.list("acme")
    assert admin.purge("acme", grace_seconds=0).removed == (stray,)
    reread = PackedObjectStore(service.objects.blobs, LocalKeyProvider(b"k" * 32))
    assert stray not in reread.list("acme") and reread.fsck("acme")["bad"] == []
    assert run_id in reread.list("acme")
