"""0.46: ``tine purge``, signed tombstones, and how push, fetch and bundles carry them."""

from __future__ import annotations

import json
import sys

import httpx
import pytest

from opentine import _bundle, _tombstone, cli
from opentine._cli_errors import NOT_FOUND, VERIFICATION_FAILED
from opentine._signed_record import RecordError
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo, _tombstones
from opentine.repository._gc import gc
from opentine.repository._holds import edit_holds, holds_path
from opentine.repository._pack_fit import fitted_pack
from opentine.repository._purge import purge
from opentine.repository.pack import inspect_pack, reachable

KEY = b"ab" * 32
SECRET_TEXT = "the step text that must go"


def _run(store: Repo, label: str = "r", text: str = SECRET_TEXT) -> str:
    run = Run(id=label, model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": text})
    return store.put_run(run, ref="heads/main").run_id


def _blob_with(store: Repo, run: str, needle: bytes) -> str:
    for oid in reachable(store, [run], include_associated=False):
        if oid.startswith("blob:") and needle in store.get(oid).body:
            return oid
    raise AssertionError("no such blob")


def _tomb(oid: str, reason: str = "erasure request") -> dict:
    return _tombstone.sign(_tombstone.build(oid, reason, "alice"), KEY, algorithm="hmac-sha256",
                           key_id="k1")  # fmt: skip


@pytest.fixture
def store(tmp_path):
    repo = Repo.init(tmp_path / "s")
    run = _run(repo)
    return repo, run, _blob_with(repo, run, SECRET_TEXT.encode())


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


# --- purge ------------------------------------------------------------------- #


@pytest.mark.parametrize("packed", [False, True], ids=["loose", "packed"])
def test_purge_removes_the_bytes_keeps_the_oid_and_fsck_reports_content_unavailable(store, packed):
    repo, run, blob = store
    if packed:
        gc(repo)
    result = purge(repo, _tomb(blob))
    assert result["purged"] and not repo.has(blob)
    assert repo.has(run) and repo.read_ref("heads/main") == run  # oid kept, nothing rehashed
    checked = repo.fsck()
    assert checked.ok and checked.content_unavailable == (blob,)
    assert (
        SECRET_TEXT.encode()
        not in b"".join(path.read_bytes() for path in repo.path.rglob("*") if path.is_file())
        or packed
    )  # a compressed pack would hide it from this scan; has() is the proof
    assert _tombstone.check(_tombstones.read(repo, blob), hmac_key=KEY)["state"] == "verified"
    again = purge(repo, _tomb(blob))
    assert again["already"] and not again["purged"]


def test_purge_refuses_a_held_blob_a_non_blob_and_an_unknown_one(store):
    repo, run, blob = store
    edit_holds(holds_path(repo), lambda rows: [*rows, {"oid": run, "target": "heads/main"}])
    with pytest.raises(ValueError, match="hold"):
        purge(repo, _tomb(blob))
    assert repo.has(blob) and _tombstones.read(repo, blob) is None
    with pytest.raises(RecordError):
        _tombstone.build(run, "x", "alice")
    with pytest.raises(KeyError):
        purge(Repo.init(repo.path.parent / "empty"), _tomb(blob))


def test_tombstone_reason_is_redacted_before_it_is_signed():
    leak = "OPENAI_API_KEY=sk-proj-" + "Zq7Xw2Lr9Tb4Nc8Vm1Hs6Jd3Kf5Gp0Ya"
    record = _tombstone.build("blob:sha256:" + "1" * 64, f"leaked {leak}", "alice")
    assert "Zq7Xw2Lr9Tb4" not in record["reason"]


def test_the_pack_of_a_purged_run_leaves_the_blob_as_a_boundary(store):
    repo, run, blob = store
    purge(repo, _tomb(blob))
    _, objects, shallow = inspect_pack(fitted_pack(repo, [run], [])[0])
    assert blob in shallow and blob not in {oid for oid, _ in objects}


# --- CLI --------------------------------------------------------------------- #


def test_cli_purge_and_list(store, tmp_path, capsys):
    repo, _run_oid, blob = store
    key = tmp_path / "k"
    key.write_text(KEY.decode(), encoding="utf-8")
    code, _ = _tine(capsys, "purge", blob, "--reason", "r", "--repo", str(repo.path))
    assert code != 0  # a tombstone is signed: no key, no purge
    code, out = _tine(capsys, "purge", blob, "--reason", "gdpr", "--key-file", str(key),
                      "--repo", str(repo.path), "--json")  # fmt: skip
    body = json.loads(out)
    assert code == 0 and body["purged"] and body["tombstone"]["oid"] == blob
    code, out = _tine(capsys, "purge", "--list", "--repo", str(repo.path), "--json")
    row = json.loads(out)["tombstones"][0]
    assert code == 0 and row["content"] == "unavailable" and row["state"] == "unchecked"
    code, out = _tine(capsys, "purge", "--list", "--key-file", str(key), "--repo",
                      str(repo.path), "--json")  # fmt: skip
    assert json.loads(out)["tombstones"][0]["state"] == "verified"
    other = tmp_path / "other"
    other.write_text("cd" * 32, encoding="utf-8")
    code, out = _tine(capsys, "purge", "--list", "--key-file", str(other), "--repo",
                      str(repo.path), "--json")  # fmt: skip
    assert code == VERIFICATION_FAILED
    assert json.loads(out)["tombstones"][0]["reason"] == "tombstone.bad-signature"
    code, _ = _tine(capsys, "purge", "blob:sha256:" + "9" * 64, "--reason", "r", "--key-file",
                    str(key), "--repo", str(repo.path))  # fmt: skip
    assert code == NOT_FOUND


# --- bundles ----------------------------------------------------------------- #


def test_a_bundle_carries_the_tombstone_and_unbundle_installs_it(store, tmp_path):
    repo, run, blob = store
    purge(repo, _tomb(blob))
    data = _bundle.create(repo, ["heads/main"])
    checked = _bundle.verify(data)
    assert [record["oid"] for record in checked.tombstones] == [blob]
    target = Repo.init(tmp_path / "t")
    _bundle.unbundle(target, data, "origin")
    assert _tombstones.read(target, blob) == _tombstones.read(repo, blob)
    result = target.fsck()
    assert result.ok and result.content_unavailable == (blob,)


def test_a_bundle_without_purges_is_unchanged(store):
    repo, _run_oid, _blob = store
    manifest_keys = json.loads(_bundle.create(repo, ["heads/main"])[48:].split(b"TINEPACK")[0])
    assert "tombstones" not in manifest_keys


def test_a_bundle_tombstone_must_name_a_boundary_of_its_pack(store):
    repo, _run_oid, blob = store
    purge(repo, _tomb(blob))
    data = _bundle.create(repo, ["heads/main"])
    checked = _bundle.verify(data)
    stray = _tomb("blob:sha256:" + "8" * 64)
    forged = _bundle.assemble(checked.pack, checked.refs, {"tombstones": [stray]})
    with pytest.raises(_bundle.BundleError, match="boundary"):
        _bundle.verify(forged)


# --- push and fetch ----------------------------------------------------------- #


def _remote(tmp_path, monkeypatch):
    from opentine.remote import (
        FilesystemObjectStore,
        Identity,
        LocalKeyProvider,
        RemoteApp,
        RemoteService,
        RoleAuthorizationPolicy,
        SQLiteBackend,
        StaticTokenIdentityProvider,
    )
    from opentine.repository import client as repository_client

    identities = StaticTokenIdentityProvider({
        "t": Identity("w", "acme", ("writer",)),
        "a": Identity("root", "acme", ("admin",)),
        "o": Identity("x", "other", ("admin",)),
    })  # fmt: skip
    service = RemoteService(
        FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32)),
        SQLiteBackend(tmp_path / "remote.sqlite3"),
        identities,
        RoleAuthorizationPolicy(),
    )
    app = RemoteApp(service, tmp_path / "state")

    def http(token: str = "t") -> httpx.Client:
        transport = httpx.WSGITransport(app=app)
        auth = {"Authorization": f"Bearer {token}"}
        return httpx.Client(base_url="http://remote", transport=transport, headers=auth)

    monkeypatch.setattr(repository_client, "_client", lambda base, token, **kw: http(token))
    return service, http


def test_push_sends_the_tombstone_and_fetch_brings_it_back(store, tmp_path, monkeypatch):
    from opentine.repository import client as repository_client

    repo, run, blob = store
    purge(repo, _tomb(blob))
    service, http = _remote(tmp_path, monkeypatch)
    assert service.capabilities()["tombstones"] is True
    repository_client.push(repo, "https://remote", tenant="acme", token="t")
    assert service.objects.tombstoned("acme", blob) and not service.objects.has("acme", blob)
    local = Repo.init(tmp_path / "local")
    repository_client.fetch(local, "https://remote", tenant="acme", token="t")
    assert local.has(run) and not local.has(blob)
    assert _tombstones.read(local, blob) == _tombstones.read(repo, blob)
    assert local.fsck().content_unavailable == (blob,)


def test_a_remote_purge_needs_the_purge_permission_and_answers_a_uniform_404(
    store, tmp_path, monkeypatch
):
    from opentine.repository import client as repository_client

    repo, run, blob = store
    service, http = _remote(tmp_path, monkeypatch)
    repository_client.push(repo, "https://remote", tenant="acme", token="t")
    path = f"/v1/tenants/acme/tombstones/{blob}"
    record = _tomb(blob)
    assert http("t").put(path, json=record).status_code == 403  # a writer cannot purge
    assert service.objects.has("acme", blob)
    assert http("o").put(path, json=record).status_code == 403  # another tenant's admin
    missing = http("t").get(path)
    unknown = http("t").get("/v1/tenants/acme/tombstones/blob:sha256:" + "7" * 64)
    garbage = http("t").get("/v1/tenants/acme/tombstones/not-an-oid")
    assert missing.status_code == unknown.status_code == garbage.status_code == 404
    assert missing.json() == unknown.json() == garbage.json()
    done = http("a").put(path, json=record)
    assert done.status_code == 201 and done.json() == {"stored": True, "purged": True}
    assert not service.objects.has("acme", blob)
    assert http("t").get(path).json()["tombstone"] == record
    assert http("o").get(f"/v1/tenants/acme/tombstones/{blob}").status_code == 403
    local = Repo.init(tmp_path / "local")
    repository_client.fetch(local, "https://remote", tenant="acme", token="t")
    assert local.has(run) and local.fsck().content_unavailable == (blob,)


def test_a_received_tombstone_never_deletes_local_bytes(store, tmp_path):
    repo, _run_oid, blob = store
    assert _tombstones.install(repo, [_tomb(blob)]) == 0
    assert repo.has(blob) and _tombstones.read(repo, blob) is None


def test_purge_is_cross_platform_about_its_paths(store):
    repo, _run_oid, blob = store
    purge(repo, _tomb(blob))
    path = _tombstones.path_for(repo, blob)
    assert path.relative_to(repo.path).as_posix() == f"tombstones/{blob[12:]}.json"
    assert sys.platform  # the layout above is the same on every platform
