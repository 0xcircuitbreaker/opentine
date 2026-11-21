"""OT-8: decoys that copy the flagged evidence cannot push a real hit out of the queue."""

from __future__ import annotations

import pytest

from opentine import _transcript_oversight as to
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_074_transcript_flags import HACK, _label, _pin, _runs, keys, repo  # noqa: F401
from tests.test_076_transcript_padding import _hack_run

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _flagged(capsys, repo, keys):  # noqa: F811
    ids = _runs(repo)
    _pin(repo)
    assert _label(capsys, repo, keys, "--run", ids["hack"][0])[0] == 0
    return ids


def test_fifty_decoys_do_not_evict_the_real_variant(capsys, repo, keys):  # noqa: F811
    _flagged(capsys, repo, keys)
    decoys = [_hack_run(repo, f"decoy-{i}", f"task 0: {HACK}") for i in range(50)]
    variant = _hack_run(repo, "loop-new", f"task 9: {HACK} variant")
    got = [i["item"] for i in to.items(repo)]
    assert any(variant in g for g in got)
    assert all(any(d in g for g in got) for d in decoys)


def test_past_the_bound_the_best_hits_are_kept(capsys, repo, keys, monkeypatch):  # noqa: F811
    ids = _flagged(capsys, repo, keys)
    monkeypatch.setattr(to, "MAX_SIMILAR_HITS", 2)
    with pytest.warns(RuntimeWarning, match="truncated"):
        report = to.similar_report(repo, to.verified_flags(repo))
    assert report["truncated"] is True
    assert len(report["hits"]) == 2
    runs = {run for _, run in report["hits"]}
    assert runs <= set(ids["hack"])
