"""0.78 review: a dataset version or eval file a loop controls cannot misstate a BOM.

A self-improving loop holds only its optimizer key. These tests show it cannot
get a dataset version into an AI-BOM by signing it itself, by leaving the key
roles unpinned, by claiming a digest its members do not have, by passing a
different claim convention, or by verdict rows that disagree or repeat keys.
"""

from __future__ import annotations

import json

import pytest

from opentine import _aibom, cli
from tests.aibom_helpers import TRAIN, dataset_version, lineage, pin_curator
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.lineage_helpers import RECORDER
from tests.promote_helpers import EVALER, fingerprint

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _export(tmp_path, variant, out, *extra) -> int:
    argv = [
        "bom",
        "export",
        variant,
        "--format",
        "cyclonedx",
        "--repo",
        tmp_path.as_posix(),
        "--dir",
        (tmp_path / "lineage").as_posix(),
        "--out",
        out.as_posix(),
        *extra,
    ]
    try:
        cli.main(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


@pytest.fixture
def built(tmp_path):
    _store, _root, child = lineage(tmp_path)
    return tmp_path, child, dataset_version(tmp_path / "v.json")


def test_dataset_version_needs_a_pinned_curator_and_fails_closed_unpinned(built) -> None:
    tmp_path, child, version = built
    out = tmp_path / "bom.json"
    spec = ("--dataset", f"training={version.as_posix()}")
    assert _export(tmp_path, child, out, *spec) == 1 and not out.exists()  # no bundle
    pin_curator(tmp_path, fingerprint(RECORDER))  # another key is the curator
    assert _export(tmp_path, child, out, *spec) == 1 and not out.exists()
    pin_curator(tmp_path, fingerprint(EVALER), optimizer=(fingerprint(EVALER),))
    assert _export(tmp_path, child, out, *spec) == 1 and not out.exists()
    pin_curator(tmp_path, fingerprint(EVALER))
    assert _export(tmp_path, child, out, *spec) == 0 and out.exists()


def test_a_claimed_digest_must_be_the_digest_of_the_members(built) -> None:
    tmp_path, child, _version = built
    pin_curator(tmp_path, fingerprint(EVALER))
    out = tmp_path / "bom.json"
    other = [{"chunks": "sha256:" + "d" * 64, "run": "run:sha256:" + "b" * 64}]
    lie = dataset_version(tmp_path / "lie.json", members=other)
    assert _export(tmp_path, child, out, "--dataset", f"training={lie.as_posix()}") == 1
    for convention in ("opentine.dataset-withdrawal/1", "opentine.integrity.canary"):
        wrong = dataset_version(tmp_path / "w.json", convention=convention)
        assert _export(tmp_path, child, out, "--dataset", f"eval={wrong.as_posix()}") == 1
    assert not out.exists()


def _row(dataset: str) -> dict:
    return {"dataset": dataset, "scorer": "s", "scorer_version": "1", "threshold": 1,
            "passed": True, "signer": "k"}  # fmt: skip


def test_verdict_rows_that_disagree_or_repeat_keys_are_refused() -> None:
    eid = "sha256:" + "1" * 64
    path = f"evals/{'1' * 64}.jsonl"
    other = "sha256:" + "2" * 64
    row = {"eval": eid, "verdicts_sha256": "x"}
    mixed = "\n".join(json.dumps(r) for r in (_row(TRAIN), _row(other))).encode()
    with pytest.raises(_aibom.BomError):
        _aibom._eval({path: mixed}, row)
    dup = f'{{"dataset": "{TRAIN}", "dataset": "{other}", "passed": true}}'.encode()
    with pytest.raises(ValueError):
        _aibom._eval({path: dup}, row)
    nan = f'{{"dataset": "{TRAIN}", "threshold": NaN, "passed": true}}'.encode()
    with pytest.raises(ValueError):
        _aibom._eval({path: nan}, row)
