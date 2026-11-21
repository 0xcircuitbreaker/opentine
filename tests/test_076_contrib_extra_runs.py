"""A contributed bundle may carry only its public run (audit OT-5).

A signed redacted-copy record names one public run; a second ref pointing at
a withdrawn run, or that run's objects in the pack, must fail ``dataset check``.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _bundle, _contrib_bundle, _dataset_licence, _redacted_copy
from opentine._dataset_withdraw import digest
from opentine._redacted_derive import _View, derive
from opentine.graph import Run, StepKind
from opentine.kernel import validate_links
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository.pack import create_pack


def _bundle_with(tmp_path, *, extra_ref: bool):
    repo = Repo.init(tmp_path / "r")

    def mk(name: str, text: str) -> str:
        run = Run(id=name, model_info="m", user_prompt=text, policies=PolicySet().to_dict())
        run.add_step(StepKind.done, {"text": text})
        return repo.put_run(run, ref=f"heads/{name}").run_id

    clean = mk("clean", "hello")
    withdrawn = mk("gone", "SECRET withdrawn content")
    key = Ed25519PrivateKey.from_private_bytes(b"\x15" * 32)
    public, objects, boundary, changed = derive(repo, clean, {})
    note = _dataset_licence.envelope(public, "MIT", False, key, "2026-11-20T00:00:00Z", ("MIT",))
    objects[note.oid] = note.encode()
    _, _, more, _ = derive(repo, withdrawn, {})
    stack = [withdrawn]
    while stack:
        oid = stack.pop()
        if oid in objects or not repo.has(oid):
            continue
        objects[oid] = repo.get(oid).encode()
        stack.extend(validate_links(repo.get(oid)))
    pack = create_pack(_View(objects, boundary | more), sorted(objects))
    record = {
        "kind": _redacted_copy.KIND,
        "copy_version": 1,
        "source_run": clean,
        "public_run": public,
        "ruleset": _contrib_bundle.RULESET,
        "objects": len(objects),
        "redacted": changed,
        "pack": "sha256:" + hashlib.sha256(pack).hexdigest(),
    }
    signed = _redacted_copy.sign(record, key, algorithm="ed25519")
    extra = {"tombstones": [], "redacted_public": signed}
    refs = {"heads/main": public}
    if extra_ref:
        refs["heads/x"] = withdrawn
    stones = [{"digest": digest(withdrawn), "date": "2026-11-20", "reason": "consent-withdrawn"}]
    return _bundle.assemble(pack, refs, extra), stones


def test_withdrawn_run_under_extra_ref_fails_check(tmp_path):
    data, stones = _bundle_with(tmp_path, extra_ref=True)
    row = _contrib_bundle.check(data, allow=("MIT",), tombstones=stones)
    assert not row["ok"]
    assert "the bundle carries refs other than the public run" in row["problems"]
    assert "the public run is tombstoned (withdrawn)" in row["problems"]


def test_withdrawn_run_objects_in_pack_fail_check(tmp_path):
    data, _ = _bundle_with(tmp_path, extra_ref=False)
    row = _contrib_bundle.check(data, allow=("MIT",))
    assert not row["ok"]
    assert any(p.startswith("the pack carries runs other than") for p in row["problems"])
