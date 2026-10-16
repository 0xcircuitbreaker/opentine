"""0.10.0 audit round 3: repository readers, writers, packs and fetch."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.kernel import ObjectEnvelope
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
from opentine.repository import Repo, _unadopted
from opentine.repository import client as repository_client
from opentine.repository._annotations import annotation_ref
from opentine.repository.pack import create_pack

FORGED = {"metadata": {"reviewed": "security-team"}, "tags": ["approved"]}


def _run(label: str = "victim") -> Run:
    run = Run(id=label)
    run.add_step(StepKind.done, {"text": label})
    return run


def _annotation(repo: Repo, run_oid: str, previous: str | None = None) -> str:
    return repo.put(
        "annotation",
        {
            "compatibility": "run-metadata-v1",
            "previous_id": previous,
            "target_id": run_oid,
            "value": FORGED,
        },
        redact=False,
    )


def _copy(source: Repo, target: Repo) -> None:
    for oid in source.iter_oids():
        target._store_envelope(ObjectEnvelope.decode(source.raw(oid), oid))


# --- B3-1: an annotation planted before its run arrives ----------------------- #


def test_an_annotation_planted_ahead_of_its_run_is_not_adopted_later(tmp_path: Path):
    origin = Repo.init(tmp_path / "origin")
    run_oid = origin.put_run(_run()).run_id
    attacker = Repo.init(tmp_path / "attacker")
    _copy(origin, attacker)
    note = _annotation(attacker, run_oid)
    planted = create_pack(attacker, [note])  # the run itself is only a shallow boundary

    victim = Repo.init(tmp_path / "victim")
    victim.import_pack(planted)
    assert note in _unadopted.read_unadopted(victim.path)
    victim.import_pack(origin.pack())  # the real run, with no annotation ref
    loaded = victim.load_run(run_oid)
    assert loaded.tags == [] and loaded.metadata == {}


def test_a_run_and_its_own_annotation_in_one_pack_are_still_adopted(tmp_path: Path):
    origin = Repo.init(tmp_path / "origin")
    source = _run()
    source.metadata = {"note": "kept"}
    run_oid = origin.put_run(source).run_id
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(origin.pack())
    assert clone.load_run(run_oid).metadata == {"note": "kept"}
    assert not _unadopted.read_unadopted(clone.path)


# --- B3-2: a co-writer pushes an annotation and its ref ----------------------- #


def _remote(tmp_path: Path, monkeypatch):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    backend = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("writer", "acme", ("writer",))}
    )
    service = RemoteService(objects, backend, identities, RoleAuthorizationPolicy())
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    transport = httpx.WSGITransport(app=RemoteApp(service, tmp_path / "state"))

    def session(*_args, **_kwargs):
        return httpx.Client(
            transport=transport,
            base_url="https://remote.example",
            headers={"authorization": "Bearer writer-token"},
        )

    monkeypatch.setattr(repository_client, "_client", session)
    return service, writer


def test_a_co_writer_cannot_relabel_a_run_you_already_held(tmp_path: Path, monkeypatch):
    service, writer = _remote(tmp_path / "remote", monkeypatch)
    alice = Repo.init(tmp_path / "alice")
    run_oid = alice.put_run(_run(), ref="heads/main").run_id
    service.install_pack(writer, "acme", alice.pack())
    service.update_ref(writer, "acme", "heads/main", run_oid, None)
    # Mallory, a writer on the shared remote: annotation plus its ref.
    mallory = Repo.init(tmp_path / "mallory")
    _copy(alice, mallory)
    note = _annotation(mallory, run_oid)
    service.install_pack(writer, "acme", create_pack(mallory, [note]))
    service.update_ref(writer, "acme", annotation_ref(run_oid), note, None)

    repository_client.fetch(alice, "https://remote.example", tenant="acme")
    loaded = alice.load_run(run_oid)
    assert loaded.tags == [] and loaded.metadata == {}
    assert alice.read_ref(annotation_ref(run_oid)) is None
    # The remote's view is kept where the owner can inspect and adopt it.
    assert alice.read_ref("remotes/origin/" + annotation_ref(run_oid)) == note

    repository_client.fetch(alice, "https://remote.example", tenant="acme", adopt_annotations=True)
    assert alice.load_run(run_oid).tags == ["approved"]


def test_a_fresh_clone_still_takes_the_remotes_annotations(tmp_path: Path, monkeypatch):
    service, writer = _remote(tmp_path / "remote", monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    run_oid = origin.put_run(_run(), ref="heads/main").run_id
    note = _annotation(origin, run_oid)
    service.install_pack(writer, "acme", origin.pack())
    service.update_ref(writer, "acme", "heads/main", run_oid, None)
    service.update_ref(writer, "acme", annotation_ref(run_oid), note, None)
    fresh = Repo.init(tmp_path / "fresh")
    repository_client.fetch(fresh, "https://remote.example", tenant="acme")
    assert fresh.load_run(run_oid).tags == ["approved"]


# --- B3-4: deep values are refused, never truncated ---------------------------- #


def _nest(depth: int):
    value: object = {"leaf": "recorded tool output"}
    for _ in range(depth):
        value = {"k": value}
    return value


def _depth(value) -> tuple[int, object]:
    count = 0
    while isinstance(value, dict) and "k" in value:
        value, count = value["k"], count + 1
    return count, value


def test_put_run_keeps_a_150_level_output_intact(tmp_path: Path):
    repo = Repo.init(tmp_path)
    run = Run(id="deep")
    run.add_step(StepKind.done, {"text": "x"}, outputs={"result": _nest(150)})
    loaded = repo.load_run(repo.put_run(run).run_id)
    step = list(loaded.steps.values())[-1] if isinstance(loaded.steps, dict) else loaded.steps[-1]
    count, leaf = _depth(step.outputs["result"])
    assert count == 150 and leaf == {"leaf": "recorded tool output"}
    assert "[MAX_DEPTH]" not in json.dumps(step.outputs)


def test_put_run_refuses_a_value_deeper_than_the_format_allows(tmp_path: Path):
    repo = Repo.init(tmp_path)
    run = Run(id="too-deep")
    run.add_step(StepKind.done, {"text": "x"}, outputs={"result": _nest(600)})
    with pytest.raises(ValueError):
        repo.put_run(run)


# --- B3-5: an interrupted shallow install stays readable ---------------------- #


def test_an_install_cut_short_after_objects_leaves_a_readable_repository(
    tmp_path: Path, monkeypatch
):
    from opentine.repository import _pack_install
    from opentine.repository.pack import reachable

    origin = Repo.init(tmp_path / "origin")
    source = _run("two")
    for index in range(3):
        source.add_step(StepKind.done, {"text": f"more {index}"})
    second = origin.put_run(source).run_id
    shallow = origin.pack(reachable(origin, [second], depth=0))
    victim = Repo.init(tmp_path / "victim")
    real = _pack_install.install_verified

    def no_space(path, data, kind, **kwargs):
        if kind == "pack":
            raise OSError(28, "No space left on device")
        return real(path, data, kind, **kwargs)

    monkeypatch.setattr(_pack_install, "install_verified", no_space)
    with pytest.raises(OSError):
        victim.import_pack(shallow)
    monkeypatch.setattr(_pack_install, "install_verified", real)
    assert victim.get(second)  # readable: its cut links are recorded as shallow
    assert victim.fsck().ok


# --- B3-6: migrate-v3 honours the run's own extra secret keys ----------------- #


def test_migrate_v2_applies_the_runs_extra_secret_keys(tmp_path: Path):
    from opentine.policies import PolicySet, RedactionPolicy

    run = Run(id="policy")
    run.add_step(StepKind.done, {"customer_ssn": "corp-internal-value-93f1c2", "q": "x"})
    path = tmp_path / "run.tine"
    run.save(path)
    # A file written before 0.9.2 enforced the policy: the field is still in clear.
    data = json.loads(path.read_text())
    data["policies"] = PolicySet(
        redaction=RedactionPolicy(extra_secret_keys=("customer_ssn",))
    ).to_dict()
    path.write_text(json.dumps(data))
    migrated = Repo.init(tmp_path / "migrated")
    result = migrated.migrate_v2(path, strict=False)
    legacy = {migrated.get(result.run_id).payload().get("legacy_blob")}
    leaking = [
        oid
        for oid in migrated.iter_oids()
        if oid not in legacy and b"corp-internal-value-93f1c2" in migrated.raw(oid)
    ]
    assert leaking == []


# --- unadopted record: a full record prunes instead of refusing every pack ----- #


def test_a_full_unadopted_record_forgets_entries_the_fallback_can_no_longer_read(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(_unadopted, "MAX_UNADOPTED", 1)
    repo = Repo.init(tmp_path)
    run_oid = repo.put_run(_run()).run_id
    gone = "annotation:sha256:" + "0" * 64
    _unadopted.record_unadopted(repo.path, [gone])
    fresh = _annotation(repo, run_oid)
    _unadopted.record_unadopted(repo.path, [fresh], repo)
    assert _unadopted.read_unadopted(repo.path) == {fresh}


def test_clone_refuses_a_target_that_already_holds_a_repository(tmp_path: Path):
    existing = Repo.init(tmp_path / "existing")
    existing.put_run(_run(), ref="heads/main")
    with pytest.raises(ValueError, match="already holds"):
        repository_client.clone("https://remote.example/v1/tenants/acme", tmp_path / "existing")


def test_fsck_reports_an_illegal_ref_file_and_a_corrupt_unadopted_record(tmp_path: Path):
    repo = Repo.init(tmp_path)
    run_oid = repo.put_run(_run(), ref="heads/main").run_id
    assert repo.fsck().ok
    # Not "Main": on a case-insensitive filesystem that just rewrites "main".
    (repo.path / "refs" / "heads" / "Feature").write_text(run_oid)
    (repo.path / ".DS_Store").write_text("junk")  # litter elsewhere stays ignored
    (repo.path / "refs" / ".DS_Store").write_text("junk")
    report = repo.fsck()
    assert not report.ok and any("Feature" in error for error in report.errors)
    (repo.path / "refs" / "heads" / "Feature").unlink()
    (repo.path / "unadopted").write_bytes(b"not-an-oid\n")
    report = repo.fsck()
    assert not report.ok and any(error.startswith("unadopted") for error in report.errors)


# --- re-audit: the advertised-ref path of a planted annotation ---------------- #


def test_an_advertised_ref_for_a_run_not_delivered_is_never_adopted(tmp_path: Path):
    """The ref path bypassed the install-time record: N stayed unadopted, its ref won."""
    origin = Repo.init(tmp_path / "origin")
    run_oid = origin.put_run(_run()).run_id
    attacker = Repo.init(tmp_path / "attacker")
    _copy(origin, attacker)
    own = attacker.put_run(_run("bait")).run_id
    note = _annotation(attacker, run_oid)
    victim = Repo.init(tmp_path / "victim")
    victim.import_pack(create_pack(attacker, [own, note]))
    advertised = {"heads/main": own, annotation_ref(run_oid): note}
    held = _unadopted.runs_held(victim, advertised)
    _unadopted.adopt_advertised_annotations(victim, advertised, held)
    assert victim.read_ref(annotation_ref(run_oid)) is None

    victim.import_pack(origin.pack())  # the real run arrives later, with no annotation
    # A later fetch that advertises the same planted ref still does not adopt it.
    _unadopted.adopt_advertised_annotations(victim, advertised, frozenset())
    assert victim.read_ref(annotation_ref(run_oid)) is None
    loaded = victim.load_run(run_oid)
    assert loaded.tags == [] and loaded.metadata == {}


def test_a_delivered_runs_own_advertised_annotation_is_still_adopted(tmp_path: Path):
    origin = Repo.init(tmp_path / "origin")
    run_oid = origin.put_run(_run()).run_id
    note = _annotation(origin, run_oid)
    fresh = Repo.init(tmp_path / "fresh")
    fresh.import_pack(origin.pack())
    advertised = {annotation_ref(run_oid): note}
    _unadopted.adopt_advertised_annotations(fresh, advertised, frozenset())
    assert fresh.read_ref(annotation_ref(run_oid)) == note


# --- final pass 4 #3: the unadopted record can no longer outgrow its reader --- #


def test_the_unadopted_byte_limit_admits_a_record_at_its_count_limit(tmp_path: Path):
    repo = Repo.init(tmp_path)
    oids = [f"annotation:sha256:{index:064x}" for index in range(_unadopted.MAX_UNADOPTED)]
    assert _unadopted.record_unadopted(repo.path, oids) == set()
    assert len(_unadopted.read_unadopted(repo.path, strict=True)) == _unadopted.MAX_UNADOPTED


def test_a_full_unadopted_record_drops_new_foreign_annotations_instead_of_failing(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(_unadopted, "MAX_UNADOPTED", 3)
    attacker = Repo.init(tmp_path / "attacker")
    planted = []
    for index in range(5):  # annotations for runs the victim does not hold
        run_oid = attacker.put_run(_run(f"elsewhere-{index}")).run_id
        planted.append((run_oid, _annotation(attacker, run_oid)))
    victim = Repo.init(tmp_path / "victim")
    own = victim.put_run(_run("own")).run_id
    with pytest.warns(RuntimeWarning, match="not installed"):
        for _, note in planted:
            victim.import_pack(create_pack(attacker, [note]))
    record = _unadopted.read_unadopted(victim.path, strict=True)
    assert len(record) == 3
    installed = [note for _, note in planted if victim.has(note)]
    assert sorted(installed) == sorted(record)  # each one recorded or absent
    for oid in attacker.iter_oids():  # the runs arrive later, without annotations
        if not oid.startswith("annotation:"):
            victim._store_envelope(ObjectEnvelope.decode(attacker.raw(oid), oid))
    for run_oid, _ in planted:
        loaded = victim.load_run(run_oid)
        assert loaded.tags == [] and loaded.metadata == {}
    assert victim.load_run(own).tags == []
    victim.put_run(_run("after"))
    assert victim.fsck().ok


def test_a_damaged_unadopted_record_fails_closed_without_breaking_loads(tmp_path: Path):
    victim = Repo.init(tmp_path / "victim")
    run_oid = victim.put_run(_run()).run_id
    _annotation(victim, run_oid)  # an unheaded chain the fallback would adopt
    assert victim.load_run(run_oid).tags == ["approved"]
    (victim.path / "unadopted").write_bytes(b"not an oid\n" * 10)
    loaded = victim.load_run(run_oid)
    assert loaded.tags == [] and loaded.metadata == {}  # adopts nothing
    victim.put_run(_run("new"))
    assert any("unadopted" in error for error in victim.fsck().errors)

    attacker = Repo.init(tmp_path / "attacker")
    other = attacker.put_run(_run("other")).run_id
    note = _annotation(attacker, other)
    with pytest.warns(RuntimeWarning, match="not installed"):
        victim.import_pack(create_pack(attacker, [note]))
    assert not victim.has(note)


# --- final pass 4 #4: unheaded lookups read only the run's own annotations ---- #


def _annotated_repo(tmp_path: Path, count: int) -> tuple[Repo, str]:
    repo = Repo.init(tmp_path)
    tagged = _run("tagged")
    tagged.tags = ["kept"]
    tagged_oid = repo.put_run(tagged).run_id
    for index in range(count):  # many annotations for a run that has a ref
        repo.put(
            "annotation",
            {"target_id": tagged_oid, "value": {"metadata": {"i": index}, "tags": []}},
            redact=False,
        )
    return repo, repo.put_run(_run("plain")).run_id


def test_unheaded_lookups_decode_only_the_runs_own_annotations(tmp_path: Path, monkeypatch):
    repo, plain = _annotated_repo(tmp_path, 120)
    repo.load_run(plain)  # builds the target index
    decoded: list[str] = []
    original = Repo.get

    def counting(self, oid):
        if oid.startswith("annotation:"):
            decoded.append(oid)
        return original(self, oid)

    monkeypatch.setattr(Repo, "get", counting)
    assert repo.load_run(plain).tags == []
    repo.put_run(_run("fresh"))
    assert decoded == []


def test_more_annotations_than_the_scan_bounds_never_fail_loads_or_puts(
    tmp_path: Path, monkeypatch
):
    from opentine.repository import _annotations, _association_index

    repo, plain = _annotated_repo(tmp_path, 12)
    monkeypatch.setattr(_association_index, "_MAX_INDEXED", 5)
    monkeypatch.setattr(_annotations, "MAX_LEGACY_OBJECTS", 1)
    assert repo.load_run(plain).tags == []
    assert repo.put_run(_run("fresh")).run_id


def test_warm_unheaded_lookups_grow_linearly_with_the_annotation_count(tmp_path: Path):
    import time

    def warm(count: int) -> float:
        repo, plain = _annotated_repo(tmp_path / str(count), count)
        repo.load_run(plain)
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            repo.load_run(plain)
            best = min(best, time.monotonic() - started)
        return best

    small, large = warm(100), warm(400)
    assert large < max(small, 0.01) * 8  # 4x annotations: listing is linear


# --- Final pass 5 #3: two unheaded annotations from a shared remote ------------ #


def test_ambiguous_unheaded_annotations_from_a_remote_never_brick_a_run(
    tmp_path: Path, monkeypatch
):
    service, writer = _remote(tmp_path / "remote", monkeypatch)
    alice = Repo.init(tmp_path / "alice")
    run_oid = alice.put_run(_run(), ref="heads/main").run_id
    service.install_pack(writer, "acme", alice.pack())
    service.update_ref(writer, "acme", "heads/main", run_oid, None)
    # Mallory, a writer: two independent unheaded annotations for Alice's run.
    mallory = Repo.init(tmp_path / "mallory")
    _copy(alice, mallory)
    first = _annotation(mallory, run_oid)
    second = mallory.put(
        "annotation",
        {
            "compatibility": "run-metadata-v1",
            "previous_id": None,
            "target_id": run_oid,
            "value": {"metadata": {"other": "x"}, "tags": ["rejected"]},
        },
        redact=False,
    )
    service.install_pack(writer, "acme", create_pack(mallory, [first, second]))

    bob = Repo.init(tmp_path / "bob")
    repository_client.fetch(bob, "https://remote.example", tenant="acme")
    with pytest.warns(RuntimeWarning, match="ambiguous"):
        loaded = bob.load_run(run_oid)
    assert loaded.tags == [] and loaded.metadata == {}

    # The run stays taggable: the new head is ref-backed and supersedes the fallback.
    loaded.tags = ["mine"]
    with pytest.warns(RuntimeWarning, match="ambiguous"):
        bob.put_run(loaded)
    assert bob.read_ref(annotation_ref(run_oid))
    assert bob.load_run(run_oid).tags == ["mine"]
    assert alice.load_run(run_oid).tags == []


# --- final pass 6 #2: a re-sent, already-adopted annotation is not un-adopted -- #


def test_a_resent_annotation_the_fallback_already_adopted_stays_adopted(tmp_path: Path):
    victim = Repo.init(tmp_path / "victim")
    run_oid = victim.put_run(_run()).run_id
    legacy = victim.put(
        "annotation",
        {
            "compatibility": "run-metadata-v1",
            "previous_id": None,
            "target_id": run_oid,
            "value": {"metadata": {"owner": "victim"}, "tags": ["prod"]},
        },
        redact=False,
    )
    assert victim.load_run(run_oid).tags == ["prod"]
    # A remote ignores the victim's haves and sends the same annotation back.
    attacker = Repo.init(tmp_path / "attacker")
    _copy(victim, attacker)
    victim.import_pack(create_pack(attacker, [legacy]))

    assert legacy not in _unadopted.read_unadopted(victim.path)
    loaded = victim.load_run(run_oid)
    assert loaded.tags == ["prod"] and loaded.metadata == {"owner": "victim"}


def test_a_new_planted_annotation_is_still_recorded_alongside_a_resent_one(tmp_path: Path):
    victim = Repo.init(tmp_path / "victim")
    run_oid = victim.put_run(_run()).run_id
    attacker = Repo.init(tmp_path / "attacker")
    _copy(victim, attacker)
    planted = _annotation(attacker, run_oid)
    victim.import_pack(create_pack(attacker, [planted]))
    assert planted in _unadopted.read_unadopted(victim.path)
    assert victim.load_run(run_oid).tags == []


# --- final pass 7 #2: advertised refs cannot make adoption quadratic --- #


def _adoption_reads(tmp_path: Path, refs: int, chain: int) -> int:
    """Object reads adopting *refs* advertised refs that all point at one *chain*."""
    repo = Repo.init(tmp_path / f"r{refs}-{chain}")
    runs = [repo.put_run(_run(f"run-{index}")).run_id for index in range(refs)]
    tip = None
    for _ in range(chain):
        tip = _annotation(repo, runs[0], tip)
    advertised = {annotation_ref(run): tip for run in runs}
    original, reads = repo.get, [0]

    def counting_get(oid, *args, **kwargs):
        reads[0] += 1
        return original(oid, *args, **kwargs)

    repo.get = counting_get
    _unadopted.adopt_advertised_annotations(repo, advertised, frozenset())
    return reads[0]


def test_many_advertised_refs_sharing_one_chain_cost_linear_reads(tmp_path: Path):
    """Each ref used to walk the whole chain again: refs x chain object reads."""
    small = _adoption_reads(tmp_path, refs=10, chain=40)
    large = _adoption_reads(tmp_path, refs=40, chain=160)
    # 4x refs and 4x chain: linear work grows ~4x; the old walk grew ~16x.
    assert large <= small * 6, (small, large)
    assert large <= 40 + 160 + 10, large


# --- final pass 10 #5: association indexes listed once per pack walk ---------- #


def test_a_pack_walk_lists_the_association_indexes_once_however_many_runs(
    tmp_path: Path, monkeypatch
):
    from opentine.repository import _associations
    from opentine.repository.pack import reachable

    for runs in (3, 24):
        repo = Repo.init(tmp_path / f"walk-{runs}")
        wants = [repo.put_run(_run(f"r{index}")).run_id for index in range(runs)]
        notes = [_annotation(repo, run) for run in wants]
        calls: list[str] = []
        real = _associations.indexed_targets

        def counted(*args, _calls=calls, _real=real, **kwargs):
            _calls.append(args[1])
            return _real(*args, **kwargs)

        monkeypatch.setattr(_associations, "indexed_targets", counted)
        found = set(reachable(repo, wants))
        monkeypatch.setattr(_associations, "indexed_targets", real)
        # one listing per association kind for the whole walk, not one per run
        assert sorted(calls) == ["annotation", "attestation"], (runs, calls)
        assert set(notes) <= found
