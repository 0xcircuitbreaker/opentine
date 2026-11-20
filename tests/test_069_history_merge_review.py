"""0.69 review: holes a loop holding only its optimizer key could use in a history merge."""

from __future__ import annotations

import json

import pytest

from opentine import _history_merge as hm
from opentine._pyz import _histmerge
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import fingerprint
from tests.query_helpers import tine
from tests.test_069_history_merge_cli import (  # noqa: F401
    AT,
    _other_side,
    _run,
    _snap,
    _write,
    room,
)

A, C = (f"run:sha256:{i:064x}" for i in (1, 3))
H = [f"{i:064x}" for i in (40, 41)]
MERGES = pytest.mark.parametrize("merge", [hm.merge, _histmerge.merge], ids=["ref", "pyz"])


def _taint_in_base() -> tuple[dict, dict, dict]:
    base = hm.empty()
    base["labels"] = {"prod": {"current": A, "history": [H[0]]}}
    base["refs"] = {"heads/main": A}
    base["holds"] = [["integrity-taint:" + C, "attestation:sha256:" + "e" * 64]]
    ours, theirs = hm.normalize(base), hm.normalize(base)
    theirs["labels"]["prod"] = {"current": C, "history": [H[0], H[1]]}
    theirs["refs"]["heads/main"] = C
    return base, ours, theirs


@MERGES
def test_a_name_never_moves_onto_a_target_held_in_the_base(merge) -> None:
    base, ours, theirs = _taint_in_base()
    found = merge(base, ours, theirs)
    assert found["merged"]["labels"]["prod"]["current"] == A
    assert found["merged"]["refs"]["heads/main"] == A
    assert {(c["kind"], c["key"]) for c in found["conflicts"]} == {
        ("held-target", "labels/prod"), ("held-target", "refs/heads/main")}  # fmt: skip


@MERGES
def test_a_name_never_moves_onto_a_target_both_sides_hold(merge) -> None:
    base, ours, theirs = _taint_in_base()
    base["holds"] = []
    ours["holds"] = theirs["holds"] = [["loop-stop:l9", C]]
    found = merge(base, ours, theirs)
    assert found["merged"]["labels"]["prod"]["current"] == A


@pytest.mark.parametrize("normalize", [hm.normalize, _histmerge.normalize], ids=["ref", "pyz"])
@pytest.mark.parametrize(("table", "name"), [
    ("lineage", "sha256:../../promotion/prod"), ("lineage", "sha256:" + "A" * 64),
    ("labels", "../prod"), ("labels", "a/b"), ("labels", "a\\b"), ("labels", ".."),
])  # fmt: skip
def test_names_that_become_paths_are_refused(normalize, table: str, name: str) -> None:
    snap = hm.empty()
    snap[table][name] = H[0] if table == "lineage" else {"current": None, "history": [H[0]]}
    with pytest.raises(ValueError):
        normalize(snap)


def _optimizer(where: dict, *, pin: bool) -> None:
    text = f'version = 1\n[roles]\noptimizer = ["{fingerprint("69" * 32)}"]\n'
    (where["repo"].path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    if pin:
        pin_roles(where["repo"].path)


def test_an_optimizer_key_cannot_land_a_label_by_merge(room, capsys) -> None:  # noqa: F811
    base = _snap(capsys, room)
    theirs, state, lineage = _other_side(room, base)
    _optimizer(room, pin=True)
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, _ = tine(capsys, "merge-history", "apply", "--repo", (room["base"] / "r").as_posix(),
                   "--base", files[0], "--theirs", files[1],
                   "--key", (room["base"] / "k.key").as_posix(), "--subject",
                   room["runs"]["b"], "--at", AT, "--theirs-state", state.as_posix(),
                   "--theirs-lineage", lineage.as_posix())  # fmt: skip
    assert code == 1
    assert _snap(capsys, room)["labels"] == base["labels"]


def test_an_unpinned_optimizer_key_is_refused_too(room, capsys) -> None:  # noqa: F811
    base = _snap(capsys, room)
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/release"] = room["runs"]["b"]
    _optimizer(room, pin=False)
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, _ = tine(capsys, "merge-history", "apply", "--repo", (room["base"] / "r").as_posix(),
                   "--base", files[0], "--theirs", files[1],
                   "--key", (room["base"] / "k.key").as_posix(), "--target",
                   "heads/release", "--at", AT)  # fmt: skip
    assert code == 1
    assert "heads/release" not in _snap(capsys, room)["refs"]
