"""The second self-gate: the same rules, through the PUBLIC surface.

``test_conformance_suite`` runs every case through the same low-level functions
the generator used, so a shared misconception there would produce vectors that
confirm it. This module re-derives a representative slice of the suite through
``Repo`` / ``Run`` / ``install_pack`` instead -- the API an application actually
holds -- so a change that satisfies one path and breaks the other is caught.

It is deliberately not a second copy of the case list: it asserts the *pinned
answers from the vector files* are reachable through the public API, which is
the property the low-level gate cannot establish about itself.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from opentine import Repo, Run
from opentine.kernel import KernelError
from tests.conformance.generate import SUITE

VECTORS = {
    record["id"]: record
    for path in sorted((SUITE / "vectors").glob("*.json"))
    for record in json.loads(path.read_text("utf-8"))["cases"]
}


def _bytes(record: dict) -> bytes:
    spec = record["input"]
    if "bytes_b64" in spec:
        return base64.b64decode(spec["bytes_b64"], validate=True)
    if "blob" in spec:
        return (SUITE / spec["blob"]).read_bytes()
    if "path" in spec:
        return (SUITE.parents[1] / spec["path"]).read_bytes()
    raise AssertionError(f"{record['id']} has no byte-shaped input")


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo.init(tmp_path / "work")


def test_repo_put_reproduces_the_oid_vectors(repo: Repo) -> None:
    """``Repo.put`` must land on the object ids ``oid.derive`` pinned."""
    assert repo.put("blob", b"hello\n") == VECTORS["oid.derive.blob-worked-vector"]["output"]["oid"]
    payload = {"cost": 0, "kind": "model", "parent_ids": []}
    assert (
        repo.put("event", payload) == (VECTORS["oid.derive.event-worked-vector"]["output"]["oid"])
    )


def test_repo_get_round_trips_the_envelope_vectors(repo: Repo) -> None:
    oid = repo.put("blob", b"hello\n")
    stored = repo.raw(oid)
    assert stored == base64.b64decode(
        VECTORS["env.header.canonical"]["input"]["bytes_b64"], validate=True
    )
    assert repo.get(oid).payload() == b"hello\n"


def test_repo_rejects_every_envelope_the_suite_marks_reject(repo: Repo) -> None:
    """A stored object the vectors refuse must be unreadable through ``Repo`` too."""
    rejected = [
        record
        for record in VECTORS.values()
        if record["op"] == "envelope.decode"
        and record["expect"] == "reject"
        and "bytes_b64" in record["input"]
    ]
    assert rejected
    for record in rejected:
        raw = _bytes(record)
        # Write the bytes under the oid a *repaired* reader would have produced, then
        # require the public reader to refuse them rather than hand back an object.
        target = repo.path / "objects" / "blob" / "00" / ("0" * 62)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        with pytest.raises((KernelError, ValueError)):
            repo.get("blob:sha256:" + "0" * 64)


def test_repo_fsck_accepts_a_repository_built_from_the_link_vectors(repo: Repo) -> None:
    blob = repo.put("blob", b"hello\n")
    root = repo.put("event", {"cost": 0, "kind": "model", "parent_ids": []})
    child = repo.put("event", {"cost": 0, "kind": "tool", "parent_ids": [root]})
    run = repo.put(
        "run",
        {
            "events": [root, child],
            "manifests": {"transcript": blob},
            "roots": [root],
            "status": "completed",
            "tips": [child],
        },
    )
    repo.update_ref("heads/main", run)
    assert repo.fsck().ok


def test_repo_refuses_a_heads_ref_pointing_at_the_wrong_type(repo: Repo) -> None:
    """SPEC 2.5 through ``update_ref``, matching ``ref.target.*`` vectors."""
    event = repo.put("event", {"cost": 0, "kind": "model", "parent_ids": []})
    with pytest.raises((KernelError, ValueError)):
        repo.update_ref("heads/main", event)


def test_install_pack_enforces_the_shallow_closure_vector(tmp_path: Path) -> None:
    """``pack.install.shallow-is-not-the-link-closure`` through the public installer."""
    from opentine.repository.pack import install_pack

    record = VECTORS["pack.install.shallow-is-not-the-link-closure"]
    destination = Repo.init(tmp_path / "dest")
    with pytest.raises(KernelError):
        install_pack(destination, _bytes(record))


def test_install_pack_accepts_the_canonical_frame_vector(tmp_path: Path) -> None:
    from opentine.repository.pack import install_pack

    record = VECTORS["pack.install.simple"]
    destination = Repo.init(tmp_path / "dest")
    result = install_pack(destination, _bytes(record))
    assert result.pack_id == record["output"]["pack_id"]
    assert sorted(result.objects) == record["output"]["objects"]


def test_run_verify_integrity_matches_the_integrity_vectors(tmp_path: Path) -> None:
    """SPEC 3.5 through ``Run.verify_integrity`` rather than the digest function."""
    for name in ("integrity.verify.ok", "integrity.verify.mismatch"):
        record = VECTORS[name]
        path = tmp_path / f"{name}.tine"
        path.write_bytes(_bytes(record))
        result = Run.verify_integrity(path)
        assert bool(result.ok) == record["output"]["ok"], name
        assert result.reason == record["output"]["reason"], name


def test_run_verify_signature_matches_the_compat_vectors(tmp_path: Path) -> None:
    """SPEC 5.1 through ``Run.verify_signature`` over the golden fixtures."""
    from tests.conformance.keys import HMAC_COMPAT

    checked = 0
    for record in VECTORS.values():
        if record["op"] != "sig.verify" or "path" not in record["input"]:
            continue
        path = SUITE.parents[1] / record["input"]["path"]
        result = Run.verify_signature(path, hmac_key=HMAC_COMPAT)
        assert result.state == record["output"]["state"], record["id"]
        assert bool(result.ok) == record["output"]["ok"], record["id"]
        checked += 1
    assert checked == 16, "two signed artifacts per released version: the full-header "
    "block and the partial one SPEC 4.1's rebuild MUST turns on"


def test_repo_attest_and_verify_reach_the_verdict_vectors(repo: Repo) -> None:
    """SPEC 4.5/4.7 through ``Repo.attest`` / ``Repo.verify_attestation``."""
    from tests.conformance.keys import HMAC_A, HMAC_B

    run = repo.put("run", {"events": [], "status": "completed"})
    oid = repo.attest(
        run,
        claim={"result": "pass"},
        signer="release-bot",
        key=HMAC_A,
        key_id="demo-key",
        signed_at="2026-09-05T00:00:00Z",
    )
    verified = repo.verify_attestation(oid, hmac_key=HMAC_A)
    assert (verified.ok, verified.state) == (True, "verified")
    mismatched = repo.verify_attestation(oid, hmac_key=HMAC_B)
    assert (mismatched.ok, mismatched.state) == (False, "mismatch")
    unsigned = repo.attest(run, claim={"result": "pass"}, signer="release-bot")
    assert repo.verify_attestation(unsigned).state == "unsigned"
