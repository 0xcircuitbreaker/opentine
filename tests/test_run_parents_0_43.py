"""0.43 ``parents[]`` on the run object (F2 groundwork), omitted when empty.

The proof that it is additive: every released fixture repository's runs keep
their oids under the new validation, a re-save with no parents writes the very
same oid, and only a run that names parents changes.
"""

from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.kernel import KernelError, ObjectEnvelope, validate_links
from opentine.repository import Repo
from opentine.repository._run_parents import run_parents, set_run_parents

COMPAT = Path(__file__).parent / "fixtures" / "compat"
RELEASES = sorted(p.name for p in COMPAT.iterdir() if (p / "repo").is_dir())


def _run(name: str) -> Run:
    run = Run(id=name)
    run.add_step(StepKind.think, {"text": name})
    return run


@pytest.mark.parametrize("release", RELEASES)
def test_released_runs_keep_their_oids(release, tmp_path):
    shutil.copytree(COMPAT / release / "repo", tmp_path / "repo")
    repo = Repo.open(tmp_path / "repo")
    runs = [oid for oid in repo.iter_oids() if oid.startswith("run:")]
    assert runs
    for oid in runs:
        envelope = repo.get(oid)  # the new kernel and run-graph checks accept it
        payload = envelope.payload()
        assert "parents" not in payload
        assert ObjectEnvelope.create("run", payload, envelope.schema).oid == oid
        assert repo.load_run(oid) is not None


def test_no_parents_is_byte_identical_and_parents_are_links(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    first = repo.put_run(_run("a")).run_id
    second = repo.put_run(_run("b")).run_id
    template = _run("m")
    plain = repo.put_run(copy.deepcopy(template)).run_id
    empty = copy.deepcopy(template)
    set_run_parents(empty, [])
    assert repo.put_run(empty).run_id == plain  # omitted when empty: the same oid

    merged = copy.deepcopy(template)
    set_run_parents(merged, [first, second, first])
    merge_id = repo.put_run(merged).run_id
    assert merge_id != plain
    payload = repo.get(merge_id).payload()
    assert run_parents(payload) == [first, second]
    assert {first, second} <= set(validate_links(repo.get(merge_id)))
    loaded = repo.load_run(merge_id)
    assert repo.put_run(loaded).run_id == merge_id  # a re-save keeps the parents
    assert repo.fsck().ok


@pytest.mark.parametrize(
    "parents",
    [[], "run:sha256:" + "0" * 64, 7, {"a": 1}, ["event:sha256:" + "0" * 64], ["x"]],
)
def test_malformed_parents_are_refused(tmp_path, parents):
    repo = Repo.init(tmp_path / "repo")
    with pytest.raises(KernelError):
        repo.put("run", {"events": [], "parents": parents})


def test_duplicate_or_missing_parents_are_refused(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    first = repo.put_run(_run("a")).run_id
    with pytest.raises(KernelError):
        repo.put("run", {"events": [], "parents": [first, first]})
    with pytest.raises(KernelError, match="missing linked object"):
        repo.put("run", {"events": [], "parents": ["run:sha256:" + "1" * 64]})
    assert repo.put("run", {"events": [], "parents": [first]}).startswith("run:")
