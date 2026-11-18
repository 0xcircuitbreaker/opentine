"""0.59: ``tine lineage record|check`` end to end, and what the check refuses.

No wall clock: the check's cost is proven by counting record reads (each
ancestor is read once however many paths reach it), not by timing.
"""

from __future__ import annotations

import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _lineage_check, cli
from opentine._lineage import record, variant_id
from opentine._lineage_check import check, read_folder
from opentine.coord import _loop_stop
from opentine.repository import Repo
from tests.lineage_helpers import RECORDER, art, key, promoted, raw
from tests.promote_helpers import AT, RUN_A, RUN_B, RUN_C

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _key_file(tmp_path):
    path = tmp_path / "recorder.key"
    path.write_bytes(RECORDER.encode())
    return path.as_posix()


def test_record_then_check_through_the_cli(tmp_path, capsys) -> None:
    decision, cand = promoted(tmp_path)
    store = (tmp_path / "lineage").as_posix()
    keyfile = _key_file(tmp_path)
    tree = art(0)["code_tree"]
    code, root = _cli(capsys, "lineage", "record", "--run", RUN_A, "--key", keyfile,
                      "--code-tree", tree, "--dir", store, "--at", AT, "--json")  # fmt: skip
    assert code == 0 and root["variant"] == variant_id({"code_tree": tree})
    code, child = _cli(capsys, "lineage", "record", "--run", RUN_B, "--key", keyfile,
                       "--prompt", art(1)["code_tree"], "--parent", root["variant"],
                       "--eval", cand.as_posix(), "--decision", decision.as_posix(),
                       "--selector", "tournament", "--dir", store, "--json")  # fmt: skip
    assert code == 0 and child["decision"] is not None
    code, out = _cli(capsys, "lineage", "check", child["variant"], "--dir", store, "--json")
    assert code == 0 and out["ok"] and out["ancestors"] == [root["variant"]]
    # The justifying eval goes missing: the variant is refused.
    shutil.rmtree(tmp_path / "lineage" / "evals")
    code, out = _cli(capsys, "lineage", "check", child["variant"], "--dir", store, "--json")
    assert code == 1
    assert [f["code"] for f in out["findings"]] == ["lineage.evidence-missing"]


def test_record_refuses_an_unsigned_eval_and_a_bad_parent(tmp_path) -> None:
    _, cand = promoted(tmp_path)
    lines = (cand / "verdicts.jsonl").read_bytes().replace(b'"signature"', b'"unsigned"')
    (cand / "verdicts.jsonl").write_bytes(lines)
    with pytest.raises(ValueError, match="must be signed"):
        record(key(RECORDER), run=RUN_B, artifacts=art(1), store=tmp_path / "l", evals=[cand])
    with pytest.raises(ValueError, match="own parent"):
        record(key(RECORDER), run=RUN_B, artifacts=art(1), store=tmp_path / "l",
               parents=[variant_id(art(1))])  # fmt: skip


def test_record_refuses_an_eval_of_another_run(tmp_path) -> None:
    """A loop cannot launder a variant with a signed eval that scored some other run."""
    _, cand = promoted(tmp_path)
    with pytest.raises(ValueError, match="another run"):
        record(key(RECORDER), run=RUN_C, artifacts=art(1), store=tmp_path / "l", evals=[cand])


def test_record_refuses_a_stopped_loop(tmp_path) -> None:
    repo = Repo.init(tmp_path / "r")
    _loop_stop.stop(repo, "opt", Ed25519PrivateKey.from_private_bytes(b"\x07" * 32), now=1)
    with pytest.raises(ValueError, match="is stopped"):
        record(key(RECORDER), run=RUN_B, artifacts=art(1), store=tmp_path / "l", loop="opt",
               repo_path=tmp_path / "r")  # fmt: skip


def test_a_decision_under_another_policy_is_a_mismatch(tmp_path) -> None:
    decision, cand = promoted(tmp_path)
    store = tmp_path / "lineage"
    good = record(key(RECORDER), run=RUN_B, artifacts=art(1), store=store, evals=[cand],
                  decision=decision, at=AT)  # fmt: skip
    assert check(read_folder(store), good["variant"])["ok"]
    other = record(key(RECORDER), run=RUN_B, artifacts=art(2), store=store, evals=[cand],
                   decision=decision, policy="f" * 64, at=AT)  # fmt: skip
    found = check(read_folder(store), other["variant"])["findings"]
    assert [f["code"] for f in found] == ["lineage.decision-mismatch"]
    assert "another policy" in found[0]["detail"]


def test_a_variant_id_that_is_not_hex_is_a_usage_error(tmp_path) -> None:
    with pytest.raises(ValueError):
        check({}, "sha256:XYZ")


@pytest.mark.parametrize("width", [8, 32])
def test_each_ancestor_is_read_once_in_a_dense_archive(tmp_path, monkeypatch, width) -> None:
    """Every variant has up to three parents among the last *width*: reads == nodes."""
    store = tmp_path / "lineage"
    ids = [raw(store, {"artifacts": art(0)})]
    count = 4 * width
    for n in range(1, count):
        parents = sorted({ids[max(0, n - 1 - k * (width // 4 or 1))] for k in range(3)})
        ids.append(raw(store, {"artifacts": art(n), "parents": parents, "mutation_run": RUN_C,
                               "evals": []}))  # fmt: skip
    reads = []
    original = _lineage_check._node

    def counted(files, v, out):
        reads.append(v)
        return original(files, v, out)

    monkeypatch.setattr(_lineage_check, "_node", counted)
    found = check(read_folder(store), ids[-1])
    assert len(reads) == len(set(reads)) == len(found["ancestors"]) + 1
    assert {f["code"] for f in found["findings"]} == {"lineage.evidence-missing"}
