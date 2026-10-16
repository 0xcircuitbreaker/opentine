"""0.10.0 audit round 3: the remote server and sync (associations, OIDC, client)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
)
from opentine.repository import Repo
from opentine.repository import pack as pack_module
from opentine.repository._traversal import TraversalQueue

MiB = 1024 * 1024


def _service(tmp_path: Path):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    backend = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("mallory", "acme", ("writer",)),
            "reader-token": Identity("reader", "acme", ("reader",)),
        }
    )
    service = RemoteService(objects, backend, identities, RoleAuthorizationPolicy())
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    reader = service.authenticate({"authorization": "Bearer reader-token"})
    return service, writer, reader


def _victim_run(local: Repo) -> str:
    source = Run(id="victim")
    source.add_step(StepKind.done, {"text": "shipped"})
    return local.put_run(source).run_id


def _blob(local: Repo, seed: int, size: int) -> str:
    # Distinct, incompressible-in-base64 bodies: a pack body carries base64.
    return local.put(
        "blob", os.urandom(size // 2).hex()[:size].encode() + bytes([seed]), redact=False
    )


# --- A3-1 / B3-3: associations never make a pack fail ------------------------ #


def test_attestation_evidence_beyond_the_body_budget_is_omitted_not_fatal(tmp_path, monkeypatch):
    """Before 0.10, two big evidence blobs made create_pack raise for the victim's run."""
    local = Repo.init(tmp_path / "local")
    run = _victim_run(local)
    blobs = [_blob(local, index, 2 * MiB) for index in range(2)]
    local.attest(run, {"k": 1}, signer="mallory", evidence_ids=blobs)
    monkeypatch.setattr(pack_module, "MAX_PACK_BODY_BYTES", 3 * MiB)
    omitted: list[str] = []
    oids = pack_module.reachable(local, [run], omitted=omitted)
    assert omitted == [run]
    assert not any(oid in oids for oid in blobs)
    assert not any(oid.startswith("attestation:") for oid in oids)
    pack_module.create_pack(local, oids, max_body=3 * MiB)  # builds


def test_a_queue_overflow_from_evidence_is_omitted_not_fatal(tmp_path, monkeypatch):
    """The queue raised a plain KernelError before the walk's OverBudget could."""
    local = Repo.init(tmp_path / "local")
    run = _victim_run(local)
    blobs = [local.put("blob", f"e{index}".encode(), redact=False) for index in range(30)]
    local.attest(run, {"k": 1}, signer="mallory", evidence_ids=blobs)
    # Shrink both bounds together, as they are equal at their real defaults.
    monkeypatch.setattr(pack_module, "MAX_PACK_OBJECTS", 20)
    monkeypatch.setitem(TraversalQueue.__init__.__kwdefaults__, "limit", 20)
    omitted: list[str] = []
    oids = pack_module.reachable(local, [run], omitted=omitted)
    assert omitted == [run] and run in oids
    assert len(oids) <= 20


def test_the_server_still_serves_a_run_a_writer_attached_huge_evidence_to(tmp_path, monkeypatch):
    service, writer, reader = _service(tmp_path / "remote")
    local = Repo.init(tmp_path / "local")
    run = _victim_run(local)
    service.install_pack(writer, "acme", local.pack())
    blobs = [_blob(local, index, 2 * MiB) for index in range(2)]
    local.attest(run, {"k": 1}, signer="mallory", evidence_ids=blobs)
    service.install_pack(writer, "acme", local.pack())
    monkeypatch.setattr(pack_module, "MAX_PACK_BODY_BYTES", 3 * MiB)
    monkeypatch.setitem(pack_module.create_pack.__kwdefaults__, "max_body", 3 * MiB)
    monkeypatch.setattr("opentine.remote.service.MAX_PACK_BODY_BYTES", 3 * MiB, raising=False)
    omitted: list[str] = []
    assert service.negotiate(reader, "acme", [run], [])
    data = service.fetch_pack(reader, "acme", [run], [], omitted=omitted)
    assert omitted == [run]
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(data)
    assert clone.has(run)


# --- hardening ---------------------------------------------------------------- #


@pytest.mark.parametrize("azp", [["client"], {"a": 1}, 7])
def test_a_non_string_azp_is_an_authentication_failure_not_a_crash(azp):
    from types import SimpleNamespace

    from opentine.remote._jwt_claims import OIDCError, validate_claims

    verifier = SimpleNamespace(
        issuer="iss", audience="api", authorized_parties=("client",), now=lambda: 100, leeway=0
    )
    claims = {"iss": "iss", "aud": "api", "azp": azp, "exp": 200}
    with pytest.raises(OIDCError):
        validate_claims(verifier, claims)


def test_ipv6_clients_share_one_slot_budget_per_64():
    from opentine.remote._http_server import _peer

    assert _peer(("2001:db8::1", 1, 0, 0)) == _peer(("2001:db8::ffff:2", 2, 0, 0))
    assert _peer(("2001:db8:0:1::1", 1, 0, 0)) != _peer(("2001:db8::1", 1, 0, 0))
    assert _peer(("::ffff:192.0.2.7", 1, 0, 0)) == _peer(("192.0.2.7", 1)) == "192.0.2.7"


def test_purge_with_no_grace_needs_force(tmp_path, capsys):
    from opentine import cli

    root = tmp_path / "root"
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            ["serve", "purge", "--root", str(root), "--tenant", "acme", "--grace-seconds", "0"]
        )
    assert "--force" in str(excinfo.value) + capsys.readouterr().err


@pytest.mark.parametrize(
    "remote",
    [
        "https://user:pw@remote.example",
        "https://remote.example/?token=abc",
        "https://remote.example/#frag",
    ],
)
def test_remote_urls_carrying_credentials_or_a_query_are_refused(remote):
    from opentine.repository._http import require_secure_remote

    with pytest.raises(ValueError, match="must not carry"):
        require_secure_remote(remote, False)


def test_remote_http_errors_name_the_path_not_the_url():
    import httpx

    from opentine.repository._http import raise_for_status

    request = httpx.Request("GET", "https://remote.example/v1/tenants/acme/refs?token=abc")
    with pytest.raises(ValueError) as excinfo:
        raise_for_status(httpx.Response(401, request=request))
    assert "token" not in str(excinfo.value) and "401" in str(excinfo.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_a_group_readable_token_file_warns(tmp_path, capsys):
    import argparse

    from opentine._repo_cli_token import _token

    path = tmp_path / "token"
    path.write_text("secret-token\n")
    path.chmod(0o644)
    assert _token(argparse.Namespace(token=None, token_file=str(path))) == "secret-token"
    assert "readable by others" in capsys.readouterr().err
    path.chmod(0o600)
    _token(argparse.Namespace(token=None, token_file=str(path)))
    assert capsys.readouterr().err == ""


# --- re-audit ------------------------------------------------------------------ #


@pytest.mark.parametrize(
    "remote",
    [
        "https://remote.example/v1/tenants/acme?access_token=SECRET",
        "https://remote.example/v1/tenants/acme#frag",
        "https://user:pw@remote.example/v1/tenants/acme",
    ],
)
def test_an_embedded_tenant_url_is_checked_as_given(remote):
    """The query used to ride along inside the tenant, into every request path."""
    from opentine.repository._http import split_remote

    with pytest.raises(ValueError, match="must not carry"):
        split_remote(remote, None)


@pytest.mark.parametrize("tenant", ["Acme", "acme%2F..", "acme%3Ftoken", "", "-acme"])
def test_a_tenant_outside_the_server_grammar_is_refused(tenant):
    from opentine.repository._http import split_remote

    with pytest.raises(ValueError):
        split_remote(f"https://remote.example/v1/tenants/{tenant}", None)


def test_a_valid_embedded_tenant_still_splits():
    from opentine.repository._http import split_remote

    assert split_remote("https://remote.example/v1/tenants/acme/", None) == (
        "https://remote.example",
        "acme",
    )
    assert split_remote("https://remote.example", "acme.prod") == (
        "https://remote.example",
        "acme.prod",
    )


def test_evidence_naming_many_events_is_omitted_at_depth_zero(tmp_path, monkeypatch):
    """One attestation citing more events than a pack may list as shallow boundaries."""
    local = Repo.init(tmp_path / "local")
    run = _victim_run(local)
    events = []
    for index in range(30):
        other = Run(id=f"other{index}")
        other.add_step(StepKind.done, {"text": str(index)})
        events.extend(local.get(local.put_run(other).run_id).payload()["events"])
    local.attest(run, {"k": 1}, signer="mallory", evidence_ids=events)
    monkeypatch.setattr(pack_module, "MAX_PACK_OBJECTS", 20)
    monkeypatch.setitem(TraversalQueue.__init__.__kwdefaults__, "limit", 20)
    omitted: list[str] = []
    oids = pack_module.reachable(local, [run], depth=0, omitted=omitted)
    assert omitted == [run]
    assert not any(oid.startswith("attestation:") for oid in oids)
    pack_module.create_pack(local, oids)  # builds: no shallow-count failure


def _incremental_setup(tmp_path: Path, monkeypatch):
    """A reader already holds the objects an attestation cites; then it fetches at depth 0."""
    from opentine.kernel import validate_links

    monkeypatch.setattr(pack_module, "MAX_PACK_OBJECTS", 40)
    monkeypatch.setitem(TraversalQueue.__init__.__kwdefaults__, "limit", 40)
    local = Repo.init(tmp_path / "server")
    source = Run(id="victim")
    for index in range(12):
        source.add_step(StepKind.done, {"text": f"s{index}"})
    run = local.put_run(source).run_id
    events: list[str] = []
    blobs: set[str] = set()
    for index in range(5):
        other = Run(id=f"o{index}")
        for step in range(5):
            other.add_step(StepKind.done, {"text": f"{index}-{step}", "pad": "x" * index})
        for event in local.get(local.put_run(other).run_id).payload()["events"]:
            events.append(event)
            blobs.update(
                link for link in validate_links(local.get(event)) if link.startswith("blob:")
            )
    cited = sorted(blobs)[:15]
    held_before = set(local.iter_oids(limit=10_000))
    local.attest(run, {"k": 1}, signer="mallory", evidence_ids=events + cited)
    available = pack_module.reachable(local, [run], depth=0)
    haves = [oid for oid in available if oid in held_before]
    return local, run, haves


def test_an_incremental_depth_zero_fetch_cannot_be_broken_by_an_attestation(tmp_path, monkeypatch):
    """Round-2 re-audit: haves turned the attestation's links into extra shallow entries."""
    from opentine.kernel import KernelError
    from opentine.repository._pack_fit import fitted_pack

    local, run, haves = _incremental_setup(tmp_path, monkeypatch)
    missing = pack_module.negotiate(local, [run], haves, depth=0)
    with pytest.raises(KernelError, match="shallow"):
        pack_module.create_pack(local, missing)  # the unguarded build still overflows
    omitted: list[str] = []
    data, carried = fitted_pack(local, [run], haves, depth=0, omitted=omitted)
    assert data and run in omitted
    assert not any(oid.startswith("attestation:") for oid in carried)


def test_a_typed_incremental_fetch_also_falls_back_to_the_graph(tmp_path, monkeypatch):
    from opentine.repository._pack_fit import fitted_pack, typed_selection

    local, run, haves = _incremental_setup(tmp_path, monkeypatch)
    omitted: list[str] = []
    select = typed_selection({"run", "event", "attestation"})
    data, carried = fitted_pack(local, [run], haves, depth=0, omitted=omitted, select=select)
    assert data and run in omitted
    assert all(oid.split(":", 1)[0] in {"run", "event", "blob"} for oid in carried)


# --- final pass #4: rolled-back association sets cannot be re-read per run -------- #


def test_association_reads_stay_bounded_however_many_runs_share_oversized_evidence(
    tmp_path, monkeypatch
):
    """A body-sized evidence set on every run was read once per run before 0.10 shipped.

    Each run's attempt was rolled back and the next run started fresh, so one fetch
    of N such runs read the set N times. The association phase's reading is now
    charged to a total that is never rolled back.
    """
    from opentine.repository import _semantic_view
    from opentine.repository._pack_work import WORK_FACTOR

    local = Repo.init(tmp_path / "local")
    blobs = [_blob(local, index, 400 * 1024) for index in range(8)]
    runs = []
    for index in range(12):
        source = Run(id=f"shared-{index}")
        source.add_step(StepKind.done, {"text": f"run {index}"})
        run = local.put_run(source).run_id
        local.attest(run, {"k": index}, signer="mallory", evidence_ids=blobs)
        runs.append(run)
    budget = 3 * MiB
    monkeypatch.setattr(pack_module, "MAX_PACK_BODY_BYTES", budget)
    # Keep the evidence out of the view's cache, as 10 MiB objects would be.
    monkeypatch.setitem(_semantic_view.SemanticView.__init__.__kwdefaults__, "max_cache_bytes", 0)
    evidence = set(blobs)
    read = {"bytes": 0}
    original = Repo.raw

    def counting_raw(self, oid):
        data = original(self, oid)
        if oid in evidence:
            read["bytes"] += len(data)
        return data

    monkeypatch.setattr(Repo, "raw", counting_raw)
    omitted: list[str] = []
    oids = pack_module.reachable(local, runs, omitted=omitted)
    assert sorted(omitted) == sorted(runs)
    assert all(run in oids for run in runs)
    # One set tried per run would read ~1.2 MiB x 12 runs; the total is now capped.
    assert read["bytes"] <= WORK_FACTOR * budget
    pack_module.create_pack(local, oids, max_body=budget)  # and the pack still builds
