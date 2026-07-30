"""Security half of the 0.4.0 fork-identity suite.

Run ids come out of UNTRUSTED artifacts and feed ``runs_dir / f"{id}.tine"``
output paths, so the properties pinned here are the ones a defect turns into a
path traversal or a silent collision: every fork id is a 64-hex digest no
matter what the artifact contains, ``verify_fork_id`` is total on hostile
records, tampering flips the verdict, and an attacker holding the shipped
artifact cannot predict the id a victim's fork will get.

The BEHAVIORAL half (two divergent forks both survive on disk, branch/intent
reaching identity through ``Run.fork``, explicit ``new_run_id`` still winning
and writing no record, MCP fork boundaries, v3 dedupe and round-trip
abstention) lands with the 0.4.0 wiring phase in this same file.
"""

from __future__ import annotations

import re

import pytest

from opentine import Agent, Run, RunStatus, StepKind
from opentine._fork_identity import (
    FORK_IDENTITY_VERSION,
    _claimed_digest,
    fork_id,
    fork_record,
    verify_fork_id,
)
from opentine._graph_types import step_id

HEX64 = re.compile(r"[0-9a-f]{64}")

HOSTILE_IDS = [
    "../owned",
    "/etc/passwd",
    "..\\..\\owned",
    "a" * 4096,
    "\u202eowned",  # RTL override
    ".",
    "-",
]


def _record(source_id="src", point="p1", retained=("p1", "s0"), **overrides):
    kwargs = {
        "source_id": source_id,
        "fork_point": point,
        "retained_ids": retained,
        "branch": "main",
        "intent": None,
        "nonce": None,
        "source_metadata": {},
    }
    kwargs.update(overrides)
    return fork_record(**kwargs)


class _NeverCalledModel:
    """Cache replay reuses recorded steps; the model must never be consulted."""

    name = "test/never"

    async def complete(self, messages, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("cache replay must not call the model")


# --------------------------------------------------------------------------------------
# Hostile artifact material can only ever become a 64-hex id
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("hostile", HOSTILE_IDS)
def test_hostile_source_material_yields_a_hex_fork_id(hostile, tmp_path):
    record = _record(source_id=hostile, point=hostile, retained=[hostile, "s0"])
    run_id = fork_id(record)
    assert HEX64.fullmatch(run_id)
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    assert (runs_dir / f"{run_id}.tine").resolve().is_relative_to(runs_dir.resolve())


@pytest.mark.parametrize("hostile", HOSTILE_IDS)
def test_run_fork_of_a_hostile_artifact_yields_a_hex_id(hostile):
    run = Run(id=hostile)
    step = run.add_step(StepKind.done, {"text": "done"})
    forked = run.fork(step.id)
    assert HEX64.fullmatch(forked.id)


def test_agent_cache_replay_of_a_hostile_run_id_yields_a_hex_id():
    # Regression for the deleted `new_run_id=f"{run.id}-replay"` concatenation,
    # which copied attacker-controlled artifact text into a run id.
    run = Run(id="../owned")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    replayed = Agent(model=_NeverCalledModel()).replay_sync(run, mode="cache")
    assert HEX64.fullmatch(replayed.id)
    assert "owned" not in replayed.id
    # Provenance survives in metadata, where it cannot steer a path.
    assert replayed.metadata["replay"]["source_run"] == "../owned"


# --------------------------------------------------------------------------------------
# An attacker holding the shipped artifact cannot predict the victim's fork id
# --------------------------------------------------------------------------------------


def test_fork_id_is_unpredictable_from_the_shipped_artifact():
    # The attacker authored the artifact, so they know every hash input except
    # the victim's locally drawn nonce: the source id, all step ids (hence the
    # fork point), the branch, and the claimed integrity digest.
    known = {
        "source_id": "attacker-src",
        "point": "step-1",
        "retained": ("step-0", "step-1"),
    }
    guesses = {
        # The pre-0.4.0 derivation the attacker could compute exactly.
        step_id(StepKind.model, {"fork": known["source_id"], "from": known["point"]}),
        # The reproducible (nonce="") id.
        fork_id(_record(known["source_id"], known["point"], known["retained"], nonce="")),
        # A guessed nonce.
        fork_id(_record(known["source_id"], known["point"], known["retained"], nonce="0" * 32)),
    }
    victim = _record(known["source_id"], known["point"], known["retained"])
    assert fork_id(victim) not in guesses
    assert HEX64.fullmatch(victim["nonce"]) is None and len(victim["nonce"]) == 32
    assert re.fullmatch(r"[0-9a-f]{32}", victim["nonce"])


def test_divergent_acts_draw_distinct_nonces_and_ids():
    records = [_record() for _ in range(32)]
    assert len({record["nonce"] for record in records}) == 32
    assert len({fork_id(record) for record in records}) == 32


def test_idempotent_act_with_empty_nonce_is_reproducible():
    first = _record(nonce="")
    second = _record(nonce="")
    assert first == second
    assert first["nonce"] == ""
    assert fork_id(first) == fork_id(second)


# --------------------------------------------------------------------------------------
# verify_fork_id: total on hostile records, and tampering flips the verdict
# --------------------------------------------------------------------------------------


def _forked_run():
    parent = Run(id="parent")
    step = parent.add_step(StepKind.done, {"text": "done"})
    record = fork_record(
        source_id=parent.id,
        fork_point=step.id,
        retained_ids={step.id},
        branch="main",
        intent={"reason": "test"},
        nonce=None,
        source_metadata=parent.metadata,
    )
    child = Run(id=fork_id(record))
    child.metadata["fork"] = record
    return child, record


def _deep(levels):
    value = {"leaf": 0}
    for _ in range(levels):
        value = {"nest": value}
    return value


def _cycle():
    value = {"version": FORK_IDENTITY_VERSION}
    value["self"] = value
    return value


CRAFTED_RECORDS = [
    5,
    "not-a-record",
    None,
    True,
    [1, 2],
    {},
    {"version": 999},
    {"version": FORK_IDENTITY_VERSION},
    {"version": FORK_IDENTITY_VERSION, "slice_size": -1},
    {"version": FORK_IDENTITY_VERSION, "slice_size": 10**9},
    {"version": FORK_IDENTITY_VERSION, "slice_size": float("inf")},
    {"version": FORK_IDENTITY_VERSION, "nonce": float("nan")},
    {"version": FORK_IDENTITY_VERSION, "nonce": object()},
    {"version": FORK_IDENTITY_VERSION, "nonce": b"raw-bytes"},
    {"version": FORK_IDENTITY_VERSION, "slice": _deep(900)},
    _cycle(),
]


@pytest.mark.parametrize(
    "crafted", CRAFTED_RECORDS, ids=[str(index) for index in range(len(CRAFTED_RECORDS))]
)
def test_verify_is_total_and_never_believes_a_crafted_record(crafted):
    run = Run(id="whatever")
    run.metadata["fork"] = crafted
    verdict = verify_fork_id(run)  # must not raise, whatever the artifact holds
    assert verdict in (False, None)


def test_verify_abstains_without_a_record():
    plain = Run(id="not-a-fork")
    assert verify_fork_id(plain) is None
    # Pre-0.4.0 forks recorded lineage under other keys; never accuse them.
    legacy = Run(id="deadbeef" * 8)
    legacy.metadata.update({"forked_from": "src", "fork_point": "p1"})
    assert verify_fork_id(legacy) is None
    assert verify_fork_id(object()) is None  # not even run-shaped


def test_verify_confirms_an_untampered_record_and_survives_save_load(tmp_path):
    child, _ = _forked_run()
    assert verify_fork_id(child) is True
    path = tmp_path / "child.tine"
    child.status = RunStatus.completed
    child.save(path)
    assert verify_fork_id(Run.load(path)) is True


@pytest.mark.parametrize(
    "field, value",
    [
        ("nonce", "0" * 32),
        ("point", "another-step"),
        ("branch", "alt"),
        ("slice", "f" * 64),
        ("slice_size", 99),
        ("source", "someone-else"),
        ("source_digest", "a" * 64),
        ("intent", "b" * 64),
    ],
)
def test_verify_detects_an_edited_record(field, value):
    child, record = _forked_run()
    assert record[field] != value
    record[field] = value
    assert verify_fork_id(child) is False


def test_verify_detects_an_edited_id_or_added_key():
    child, record = _forked_run()
    record["extra"] = "smuggled"
    assert verify_fork_id(child) is False
    _, stolen = _forked_run()
    imposter = Run(id="../owned")
    imposter.metadata["fork"] = stolen  # a genuine record under a swapped id
    assert verify_fork_id(imposter) is False


# --------------------------------------------------------------------------------------
# _claimed_digest: the integrity block is untrusted and only ever shape-checked
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        "text",
        [],
        {},
        {"integrity": None},
        {"integrity": "x" * 64},
        {"integrity": {}},
        {"integrity": {"digest": None}},
        {"integrity": {"digest": 7}},
        {"integrity": {"digest": "abc"}},
        {"integrity": {"digest": "A" * 64}},  # uppercase is not what the writer emits
        {"integrity": {"digest": "g" * 64}},
        {"integrity": {"digest": "a" * 63}},
        {"integrity": {"digest": "a" * 65}},
        {"integrity": {"digest": {"nested": "a" * 64}}},
    ],
)
def test_claimed_digest_rejects_every_malformed_integrity_shape(metadata):
    assert _claimed_digest(metadata) == ""
    assert _record(source_metadata=metadata)["source_digest"] == ""


def test_claimed_digest_accepts_only_a_64_hex_claim():
    metadata = {"integrity": {"algorithm": "sha256", "digest": "ab" * 32}}
    assert _claimed_digest(metadata) == "ab" * 32
    assert _record(source_metadata=metadata)["source_digest"] == "ab" * 32


# ======================================================================================
# BEHAVIORAL half of the 0.4.0 fork-identity suite (wiring phase)
#
# The security half above pins the path-safety and totality properties of the identity
# core in isolation. These tests pin the wired behaviour through the public APIs: the
# defect (two divergent forks silently sharing one id/file) is gone, branch and intent
# reach identity, an explicit id still wins, and every entry point mints a verifiable id.
# ======================================================================================

HMAC_KEY = b"0123456789abcdef0123456789abcdef"


def _parent(run_id="parent"):
    parent = Run(id=run_id, model_info="m")
    root = parent.add_step(StepKind.model, {"text": "plan"})
    parent.status = RunStatus.completed
    return parent, root


# --------------------------------------------------------------------------------------
# The defect: two divergent forks of one point both survive and stay addressable
# --------------------------------------------------------------------------------------


def test_two_divergent_library_forks_both_survive_and_resolve(tmp_path):
    from opentine.index import RunIndex

    runs = tmp_path / "runs"
    runs.mkdir()
    parent, root = _parent()

    left = parent.fork(root.id)
    right = parent.fork(root.id)
    assert left.id != right.id  # distinct acts, distinct ids -> nothing to overwrite

    left.add_step(StepKind.done, {"text": "RESULT-A"}, parent_id=root.id)
    right.add_step(StepKind.done, {"text": "RESULT-B"}, parent_id=root.id)
    left.status = right.status = RunStatus.completed
    left.save(runs / f"{left.id}.tine")
    right.save(runs / f"{right.id}.tine")

    survivors = {Run.load(path).steps[-1].inputs["text"] for path in runs.glob("*.tine")}
    assert survivors == {"RESULT-A", "RESULT-B"}  # neither destroyed the other

    index = RunIndex.open(runs)
    index.sync()
    assert index.lookup(left.id).run_id == left.id
    assert index.lookup(right.id).run_id == right.id


# --------------------------------------------------------------------------------------
# Branch and intent reach identity; the wall clock does not; explicit ids still win
# --------------------------------------------------------------------------------------


def test_branch_and_intent_each_reach_identity():
    parent, root = _parent()
    base = parent.fork(root.id, intent={"reason": "A"}, nonce="")
    branched = parent.fork(root.id, branch="alt", intent={"reason": "A"}, nonce="")
    reintended = parent.fork(root.id, intent={"reason": "B"}, nonce="")
    assert base.id != branched.id  # branch was invisible to identity before 0.4.0
    assert base.id != reintended.id  # declared intent now reaches the id


def test_fork_id_is_independent_of_the_wall_clock():
    first = Run(id="p", model_info="m", created_at=1_000.0)
    root_a = first.add_step(StepKind.model, {"text": "x"})
    second = Run(id="p", model_info="m", created_at=9_999.0)
    root_b = second.add_step(StepKind.model, {"text": "x"})
    fork_a = first.fork(root_a.id, intent={"reason": "same"}, nonce="")
    fork_b = second.fork(root_b.id, intent={"reason": "same"}, nonce="")
    assert fork_a.id == fork_b.id  # created_at is deliberately excluded from the basis


def test_explicit_new_run_id_wins_and_records_no_basis():
    parent, root = _parent()
    parent.metadata["integrity"] = {"algorithm": "sha256", "digest": "a" * 64}
    parent.metadata["fork"] = {"version": FORK_IDENTITY_VERSION, "source": "grandparent"}
    named = parent.fork(root.id, new_run_id="explicit-name", intent={"reason": "A"})
    assert named.id == "explicit-name"
    assert "fork" not in named.metadata  # an explicit id is not a derived act
    assert "integrity" not in named.metadata  # the source's digest is never inherited
    assert verify_fork_id(named) is None  # no record -> no verdict


def test_derived_fork_drops_inherited_source_provenance_but_records_its_own():
    parent, root = _parent()
    parent.metadata["integrity"] = {"algorithm": "sha256", "digest": "a" * 64}
    parent.metadata["fork"] = {"version": FORK_IDENTITY_VERSION, "source": "grandparent"}
    child = parent.fork(root.id, intent={"reason": "A"})
    assert child.metadata["fork"]["source"] == parent.id  # its own basis, not the source's
    assert "integrity" not in child.metadata  # the parent's digest is not claimed
    assert child.metadata["fork"]["source_digest"] == "a" * 64  # but it is bound to
    assert verify_fork_id(child) is True


def test_chained_fork_records_the_immediate_parent(tmp_path):
    grandparent, root = _parent("grandparent")
    grandparent.save(tmp_path / "g.tine")
    grandparent = Run.load(tmp_path / "g.tine")  # now carries a real integrity digest

    parent = grandparent.fork(root.id, intent={"reason": "p"})
    parent.status = RunStatus.completed
    parent.save(tmp_path / "p.tine")
    parent = Run.load(tmp_path / "p.tine")

    child = parent.fork(parent.steps[0].id, intent={"reason": "c"})
    assert child.metadata["fork"]["source"] == parent.id
    assert child.metadata["fork"]["source_digest"] == parent.metadata["integrity"]["digest"]
    assert verify_fork_id(child) is True


# --------------------------------------------------------------------------------------
# Entry points: CLI, MCP, and v3 all mint verifiable (or honestly-abstaining) ids
# --------------------------------------------------------------------------------------


def test_cli_fork_twice_writes_two_hex_stemmed_verifiable_artifacts(monkeypatch, tmp_path):
    import sys

    from opentine import cli

    runs_dir = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    source = tmp_path / "source.tine"
    run = Run(id="source", model_info="m")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(source)

    def _fork():
        monkeypatch.setattr(sys, "argv", ["tine", "fork", str(source), "--from-step", "0"])
        cli.main()

    _fork()
    _fork()

    artifacts = sorted(runs_dir.glob("*.tine"))
    assert len(artifacts) == 2  # the second fork no longer collides with the first
    for artifact in artifacts:
        assert HEX64.fullmatch(artifact.stem)
        assert verify_fork_id(Run.load(artifact)) is True


def test_mcp_forks_one_point_twice_with_distinct_reasons_both_verify(tmp_path):
    import opentine.mcp_server as mcp

    source = Run(id="mcp-src", model_info="m")
    source.add_step(StepKind.done, {"text": "done"})
    source.status = RunStatus.completed
    source.save(tmp_path / "mcp-src.tine")

    first = mcp.fork_run_file("mcp-src", 0, runs_dir=tmp_path, reason="approach A")
    second = mcp.fork_run_file("mcp-src", 0, runs_dir=tmp_path, reason="approach B")
    assert first["new_run_id"] != second["new_run_id"]

    run_a, run_b = Run.load(first["path"]), Run.load(second["path"])
    assert verify_fork_id(run_a) is True and verify_fork_id(run_b) is True
    # The stated reason reaches identity: distinct reasons -> distinct intent digests.
    assert run_a.metadata["fork"]["intent"] != run_b.metadata["fork"]["intent"]
    assert run_a.metadata["fork_reason"] == "approach A"


def test_v3_native_forks_dedupe_and_abstain_while_a_v2_fork_round_trips_verifiable(tmp_path):
    from opentine.repository import Repo

    repo = Repo.init(tmp_path / "repo")
    source = Run(id="v3-src", model_info="m")
    root = source.add_step(StepKind.model, {"text": "root"})
    source.add_step(StepKind.done, {"text": "done"}, parent_id=root.id)
    source.status = RunStatus.completed
    stored = repo.put_run(source, ref="heads/main")

    # Native v3 forks are content-addressed: forking one event twice dedupes,
    # and the loaded run carries no v2 fork record, so verify honestly abstains.
    first = repo.fork(stored.run_id, stored.event_map[root.id])
    second = repo.fork(stored.run_id, stored.event_map[root.id])
    assert first == second
    assert verify_fork_id(repo.load_run(first)) is None

    # A v2 fork put and loaded back keeps its v2 id and recorded basis: the round
    # trip preserves provenance, so the fork still verifies as its own act.
    v2_fork = source.fork(root.id, intent={"reason": "keep"})
    v2_fork.status = RunStatus.completed
    round_tripped = repo.load_run(repo.put_run(v2_fork).run_id)
    assert round_tripped.id == v2_fork.id
    assert verify_fork_id(round_tripped) is True


def test_signing_covers_the_fork_record_while_integrity_ignores_metadata(tmp_path):
    import json

    parent, root = _parent()
    child = parent.fork(root.id, intent={"reason": "signed"})
    child.status = RunStatus.completed
    path = tmp_path / "child.tine"
    child.save(path, sign_key=HMAC_KEY)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert Run.verify_signature(data, hmac_key=HMAC_KEY).ok
    assert Run.verify_integrity(data).ok

    data["metadata"]["fork"]["nonce"] = "0" * 32  # tamper with the signed basis
    tampered = Run.verify_signature(data, hmac_key=HMAC_KEY)
    assert not tampered.ok  # the signature now covers metadata.fork
    # metadata is outside the integrity digest, so integrity is unmoved -- three
    # independent signals (signature, integrity, verify_fork_id) by design.
    assert Run.verify_integrity(data).ok
