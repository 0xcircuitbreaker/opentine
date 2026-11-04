"""0.35 audit hardening: crash-stale ref staging, sidecar caps and locking, bundle sig blocks."""

from __future__ import annotations

import secrets
import threading
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine._bundle_sigs import MAX_BLOCK_BYTES, _check_entry
from opentine.kernel import canonical_json
from opentine.repository import Repo
from opentine.repository import _sig_sidecar as sidecar


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return Repo.init(tmp_path)


def _run(store: Repo, label: str) -> str:
    run = Run(id=f"r{label}", model_info="m")
    run.add_step(StepKind.model, {"text": label}, {"text": "ok"})
    return store.put_run(run).run_id


def test_committed_journal_with_stale_staging_file_recovers(repo):
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_ref("tags/t1", a)
    repo.update_ref("tags/other", a)
    base = Path(repo.path)
    (base / "refs" / "tags" / "t1..lock").write_bytes(b"")  # died after the commit point
    tid = secrets.token_hex(16)
    (base / "txn").mkdir(exist_ok=True)
    journal = {
        "actor": "x",
        "format": "opentine-ref-txn/1",
        "id": tid,
        "updates": [{"new": b, "old": a, "ref": "tags/t1"}],
    }
    (base / "txn" / f"{tid}.json").write_bytes(canonical_json(journal))
    repo.update_ref("tags/other", b)  # used to raise FileExistsError forever
    assert not (base / "txn" / f"{tid}.json").exists()
    assert not (base / "refs" / "tags" / "t1..lock").exists()


def _block(n: int, pad: int = 0) -> dict:
    return {
        "alg": "ed25519",
        "key_id": f"k{n}",
        "scheme": "tine-sig/3",
        "signed_at": "2026-01-01T00:00:00Z",
        "signer": "s",
        "value": "00" * 64 + "a" * pad,
    }


def test_sidecar_write_refuses_to_exceed_read_cap(repo, monkeypatch):
    root = _run(repo, "a")
    monkeypatch.setattr(sidecar, "MAX_SIDECAR_BYTES", 2048)
    sidecar.add_signatures(repo, root, None, [_block(0)])
    with pytest.raises(ValueError, match="would exceed"):
        sidecar.add_signatures(repo, root, None, [_block(1, pad=4096)])
    assert len(sidecar.entries_for(repo, root)) == 1  # still readable


def test_concurrent_signers_keep_every_block(repo):
    root = _run(repo, "a")
    threads = [
        threading.Thread(target=sidecar.add_signatures, args=(repo, root, None, [_block(i)]))
        for i in range(16)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(sidecar.entries_for(repo, root)) == 16


def test_bundle_sig_blocks_are_shape_and_size_checked():
    from opentine._bundle import BundleError

    _check_entry({"annotations_head": None, "block": _block(0)})
    with pytest.raises(BundleError, match="unknown keys"):
        _check_entry({"annotations_head": None, "block": {**_block(0), "junk": 1}})
    with pytest.raises(BundleError, match="exceeds"):
        _check_entry({"annotations_head": None, "block": _block(0, pad=MAX_BLOCK_BYTES)})
