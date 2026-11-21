"""OT-7: padding a run's prompt does not hide it from similar-to-known-bad items."""

from __future__ import annotations

import pytest

from opentine._transcript_oversight import items
from opentine.graph import Run, StepKind
from opentine.repository import _search_index
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_074_transcript_flags import (  # noqa: F401
    HACK,
    WORK,
    _label,
    _pin,
    _runs,
    keys,
    repo,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _hack_run(repo, name, prompt):  # noqa: F811
    run = Run(id=name, model_info="m", user_prompt=prompt)
    for j in range(3):
        run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"{HACK} {j}"}})
    run.add_step(StepKind.done, {"text": "done"})
    return repo.put_run(run).run_id


def _flagged(capsys, repo, keys):  # noqa: F811
    ids = _runs(repo)
    _pin(repo)
    assert _label(capsys, repo, keys, "--run", ids["hack"][0])[0] == 0
    return ids


def test_steps_after_an_oversized_prompt_are_still_indexed(repo):  # noqa: F811
    oid = _hack_run(repo, "pad", (WORK + " ") * 20_000)
    _, docs = _search_index.extract(repo, oid)
    assert HACK in docs[0]
    assert len(docs[0].encode()) <= _search_index.MAX_INDEX_TEXT_PER_RUN + 4096


@pytest.mark.parametrize("size", [200_000, 1_040_000])
def test_a_padded_copy_of_a_flagged_run_is_still_queued(capsys, repo, keys, size):  # noqa: F811
    _flagged(capsys, repo, keys)
    plain = _hack_run(repo, "loop-new", f"task 9: {HACK}")
    padded = _hack_run(repo, "loop-pad", ((WORK + " ") * 20_000)[:size])
    got = [i["item"] for i in items(repo)]
    assert any(plain in g for g in got)
    assert any(padded in g for g in got)


def test_padding_with_benign_runs_alone_opens_nothing(capsys, repo, keys):  # noqa: F811
    ids = _flagged(capsys, repo, keys)
    run = Run(id="benign-pad", model_info="m", user_prompt=((WORK + " ") * 20_000)[:200_000])
    run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": WORK}})
    benign = repo.put_run(run).run_id
    got = [i["item"] for i in items(repo)]
    assert not any(benign in g for g in got)
    assert not any(w in g for w in ids["work"] for g in got)
