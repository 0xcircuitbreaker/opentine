"""0.35 bundle hardening: tracking-ref collisions and sidecar install order."""

from __future__ import annotations

import pytest

from opentine import Run, StepKind, _bundle
from opentine.repo import Repo
from opentine.repository._sig_sidecar import add_signatures, entries_for, sidecar_path


def _run(run_id: str) -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": run_id}, {"a": 1})
    return run


def _ed25519_block(root: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine._signing_v4 import SCHEME_V3, artifact_message
    from opentine._signing_verify import sign_block

    view = {"annotations": [], "root": root}
    return sign_block(
        lambda header: artifact_message(view, header),
        Ed25519PrivateKey.generate(),
        algorithm="ed25519",
        scheme=SCHEME_V3,
    )


def _signed(tmp_path, tamper: bool = False) -> tuple[Repo, str, bytes]:
    source = Repo.init(tmp_path / "src")
    root = source.put_run(_run("signed"), ref="heads/main").run_id
    block = _ed25519_block(root)
    if tamper:
        block = {**block, "signer": "mallory"}  # header edited after signing
    add_signatures(source, root, None, [block])
    return source, root, _bundle.create(source, ["heads/main"])


def test_colliding_tracking_refs_are_refused_before_any_install(tmp_path):
    source = Repo.init(tmp_path / "src")
    first = source.put_run(_run("one"), ref="heads/tags/x").run_id
    second = source.put_run(_run("two"), ref="heads/main").run_id
    data = _bundle.create_refs(source, {"heads/tags/x": first, "tags/x": second})
    with pytest.raises(_bundle.BundleError, match="collide"):
        _bundle.verify(data)
    target = Repo.init(tmp_path / "dst")
    with pytest.raises(_bundle.BundleError, match="collide"):
        _bundle.unbundle(target, data, "src")
    assert not target.has(first) and not target.has(second)
    assert not target.list_refs()


def test_sidecars_are_not_installed_when_the_ref_update_fails(tmp_path):
    pytest.importorskip("cryptography")
    source, root, data = _signed(tmp_path)
    target = Repo.init(tmp_path / "dst")
    other = target.put_run(_run("diverged"), ref="heads/x").run_id
    target.update_refs([("remotes/src/main", other, None)])
    with pytest.raises(_bundle.BundleError, match="fast-forward"):
        _bundle.unbundle(target, data, "src")
    assert not sidecar_path(target, root).exists()
    _bundle.unbundle(target, data, "src", force=True)
    assert entries_for(target, root) == entries_for(source, root)


def test_a_forged_ed25519_block_is_refused(tmp_path):
    pytest.importorskip("cryptography")
    _, root, data = _signed(tmp_path, tamper=True)
    with pytest.raises(_bundle.BundleError, match="does not verify"):
        _bundle.verify(data)
    target = Repo.init(tmp_path / "dst")
    with pytest.raises(_bundle.BundleError):
        _bundle.unbundle(target, data, "src")
    assert not sidecar_path(target, root).exists()
