"""0.60 advisory reward-hack detectors over the committed red-team corpus.

Count-based only: >= 27/30 seeded hacks detected with their manifest class,
false-positive rate <= 5% on 200 benign refactor runs. No timing.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from opentine import _integrity_advisory as det
from opentine._integrity_advisory_evidence import advise, render

DATA = Path(__file__).parent / "data" / "integrity_redteam"
ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    return json.loads((DATA / name).read_bytes().decode("utf-8"))


def _benign() -> list[dict]:
    lines = (DATA / "benign.jsonl").read_bytes().decode("utf-8").splitlines()
    return [json.loads(x) for x in lines if x.strip()]


def test_manifest_lists_thirty_hacks_across_every_class():
    man = _load("manifest.json")
    assert len(man["hacks"]) >= 30
    assert {h["code"] for h in man["hacks"]} == set(det.ADVISORY_CODES)
    assert [h["id"] for h in man["hacks"]] == [r["id"] for r in _load("hacks.json")]
    assert len(_benign()) == man["benign"] == 200


def test_at_least_27_of_30_seeded_hacks_detected_with_their_class():
    man = {h["id"]: h["code"] for h in _load("manifest.json")["hacks"]}
    hits = [r["id"] for r in _load("hacks.json") if man[r["id"]] in advise(r)["codes"]]
    assert len(hits) >= 27, sorted(set(man) - set(hits))


def test_false_positive_rate_on_benign_refactors_at_most_five_percent():
    flagged = [r["id"] for r in _benign() if advise(r)["findings"]]
    assert len(flagged) * 100 <= 5 * 200, flagged


def test_advisory_findings_never_block_by_default():
    for r in _load("hacks.json"):
        rep = advise(r)
        assert rep["findings"] and rep["blocking"] is False and rep["exit_code"] == 0
        assert all(f["code"].startswith("advisory:") for f in rep["findings"])
    rep = advise(_load("hacks.json")[0], {"block_on_advisory": True})
    assert rep["blocking"] is True and rep["exit_code"] == 1


def test_render_routes_each_finding_to_one_output_line():
    rep = advise(_load("hacks.json")[0])
    out = render(rep)
    assert out.splitlines()[0].startswith("advisory:test-deleted tests/test_core.py:")
    assert render(advise(_benign()[1])) == ""


@pytest.mark.parametrize(
    "line",
    [
        "@pytest.mark.skip",
        "    pytest.skip('x')",
        "@pytest.mark.skipif(sys.platform == 'x', reason='')",
        "@unittest.skipIf(True, 'x')",
        "    self.skipTest('x')",
        "it.skip('a', () => {})",
        "test.only('a', () => {})",
        "xit('a', () => {})",
    ],
)
def test_skip_dialects(line):
    run = {"diff": [{"path": "tests/test_a.py", "added": [line]}]}
    assert advise(run)["codes"] == ["advisory:test-skipped-added"]


def test_moved_test_and_kept_skip_are_not_findings():
    run = {"diff": [{"path": "tests/test_a.py",
                     "added": ["def test_x():", "@pytest.mark.skip"],
                     "removed": ["def test_x():", "@pytest.mark.skip"]}]}  # fmt: skip
    assert advise(run)["findings"] == []


def test_windows_style_paths_are_classified_as_tests():
    assert det.is_test_path("tests\\test_a.py") and det.is_test_path("pkg\\conftest.py")
    assert not det.is_test_path("src/attestation.py")


def test_findings_are_json_serialisable_and_sorted():
    rep = advise(_load("hacks.json")[20])
    assert json.loads(json.dumps(rep)) == rep
    keys = [(f["code"], f["path"], f["detail"]) for f in rep["findings"]]
    assert keys == sorted(keys)


def test_committed_corpus_matches_its_generator(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "gen_redteam", ROOT / "scripts" / "gen_integrity_redteam.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main(tmp_path)
    for name in ("manifest.json", "hacks.json", "benign.jsonl"):
        assert (tmp_path / name).read_bytes() == (DATA / name).read_bytes(), name
