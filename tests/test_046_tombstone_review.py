"""0.46 review: a remote purge honours holds by reach, stays purged, and forgets the index row."""

from __future__ import annotations

from opentine.repository import _holds
from opentine.repository import client as repository_client
from tests.test_046_tombstones import _remote, _tomb, store  # noqa: F401  (fixture)


def test_a_remote_purge_refuses_a_blob_a_held_run_reaches(store, tmp_path, monkeypatch):  # noqa: F811
    repo, run, blob = store
    service, http = _remote(tmp_path, monkeypatch)
    repository_client.push(repo, "https://remote", tenant="acme", token="t")
    holds = tmp_path / "objects" / ".holds" / "acme"
    _holds.edit_holds(holds, lambda rows: [{"oid": run, "target": run}])
    response = http("a").put(f"/v1/tenants/acme/tombstones/{blob}", json=_tomb(blob))
    assert response.status_code in (403, 409)
    assert service.objects.has("acme", blob) and not service.objects.tombstoned("acme", blob)


def test_a_purged_blob_is_not_restored_by_a_push_and_leaves_the_index(
    store,  # noqa: F811
    tmp_path,
    monkeypatch,
):
    repo, run, blob = store
    service, http = _remote(tmp_path, monkeypatch)
    repository_client.push(repo, "https://remote", tenant="acme", token="t")
    done = http("a").put(f"/v1/tenants/acme/tombstones/{blob}", json=_tomb(blob))
    assert done.status_code == 201
    with service.index.exclusive() as database:
        rows = database.execute(
            "SELECT count(*) FROM objects WHERE tenant=? AND oid=?", ("acme", blob)
        ).fetchone()[0]
    assert rows == 0
    # The writer still holds the bytes; a forced full re-push must not bring them back.
    from opentine.remote import Identity
    from opentine.repository.pack import create_pack, reachable

    pack = create_pack(repo, sorted(reachable(repo, [run], include_associated=False)))
    service.install_pack(Identity("w", "acme", ("writer",)), "acme", pack)
    assert not service.objects.has("acme", blob)
    assert service.objects.has("acme", run)
