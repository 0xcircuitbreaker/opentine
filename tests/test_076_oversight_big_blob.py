"""OT-3: one run with a blob over 1 MiB must not crash the oversight queue."""

from __future__ import annotations

import pytest

from opentine import _oversight_queue
from opentine._transcript_corpus import from_repo
from opentine.graph import Run, StepKind
from opentine.kernel import KernelError
from opentine.repository import _search_index
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_074_transcript_flags import HACK, _label, _pin, _runs, keys, repo  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _big(repo, name="big"):  # noqa: F811
    run = Run(id=name, model_info="m", user_prompt="x " * 600_000)  # 1.2 MB, a legitimate size
    run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"{HACK} 0"}})
    return repo.put_run(run).run_id


def test_a_blob_over_the_index_limit_is_read_as_a_bounded_prefix(repo):  # noqa: F811
    oid = _big(repo)
    _, docs = _search_index.extract(repo, oid)
    assert docs[0].startswith("x x x")
    assert len(docs[0].encode()) <= _search_index.MAX_INDEX_TEXT_PER_RUN + 4096


def test_the_oversight_queue_survives_a_run_with_a_big_blob(capsys, repo, keys):  # noqa: F811
    ids = _runs(repo)
    _pin(repo)
    assert _label(capsys, repo, keys, "--run", ids["hack"][0])[0] == 0
    big = _big(repo)
    assert big in from_repo(repo)
    got = [i["item"] for i in _oversight_queue._sources(repo)]
    assert any(g.startswith("transcript:attestation:") for g in got)


def test_a_run_that_cannot_be_read_is_skipped_not_fatal(repo, monkeypatch):  # noqa: F811
    ids = _runs(repo, n_hack=1, n_work=1)
    real = _search_index.extract

    def broken(r, oid):
        if oid == ids["hack"][0]:
            raise KernelError("repository blob exceeds the inspection limit")
        return real(r, oid)

    monkeypatch.setattr(_search_index, "extract", broken)
    assert set(from_repo(repo)) == {ids["work"][0]}


def test_one_failing_source_does_not_empty_the_queue(capsys, repo, keys, monkeypatch):  # noqa: F811
    from opentine import _transcript_oversight, _weight_custody_review

    ids = _runs(repo)
    _pin(repo)
    assert _label(capsys, repo, keys, "--run", ids["hack"][0])[0] == 0

    def boom(_repo):
        raise RuntimeError("source failed")

    monkeypatch.setattr(_weight_custody_review, "items", boom)
    with pytest.warns(RuntimeWarning, match="custody"):
        got = [i["item"] for i in _oversight_queue._sources(repo)]
    assert any(g.startswith("transcript:") for g in got)
    assert _transcript_oversight.verified_flags(repo)
