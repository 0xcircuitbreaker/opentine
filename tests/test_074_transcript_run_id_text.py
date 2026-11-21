"""A run's analysed text does not carry its own object id (0.74).

The id is a content hash over the run's wall-clock ``created_at``, so leaving
it in the text gave every run a random high-IDF token: the same runs recorded
at another moment (another test invocation, another CI machine) clustered
differently, and the e2e acceptance test failed intermittently (first seen on
windows-latest). Re-recording the same runs at other times must give the same
texts and the same clusters.
"""

from __future__ import annotations

from opentine._transcript_cluster import kmeans
from opentine._transcript_corpus import from_repo
from opentine._transcript_space import Space
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from tests.test_074_transcript_analysis_e2e import HACK, WORK


def _corpus(path, created_at: float) -> tuple[dict[str, str], dict[str, str]]:
    repo = Repo.init(path)
    names = {}
    for name, text in [(f"hack-{i}", HACK) for i in range(4)] + [
        (f"work-{i}", t) for i, t in enumerate(WORK * 2)
    ]:
        run = Run(id=name, model_info="m", user_prompt=text)
        run.created_at = created_at
        for j in range(3):
            run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"{text} {j}"}})
        names[repo.put_run(run).run_id] = name
    return {names[oid]: text for oid, text in from_repo(repo).items()}, names


def test_the_run_id_is_not_part_of_the_analysed_text(tmp_path):
    texts, names = _corpus(tmp_path / "a", 1_000_000.0)
    for oid in names:
        assert oid not in texts[names[oid]]
        assert oid.split(":")[-1] not in texts[names[oid]]


def _groups(texts: dict[str, str], names: dict[str, str]) -> list[list[str]]:
    space = Space({oid: texts[name] for oid, name in names.items()})
    return sorted(sorted(names[m] for m in c["members"]) for c in kmeans(space, 5)["clusters"])


def test_the_same_runs_recorded_at_other_times_cluster_alike(tmp_path):
    first, names = _corpus(tmp_path / "a", 1_000_000.0)
    expected = _groups(first, names)
    assert ["hack-0", "hack-1", "hack-2", "hack-3"] in expected
    for n in range(12):
        texts, names = _corpus(tmp_path / f"b{n}", 1_795_226_495.2 + 0.015 * n)
        assert texts == first
        assert _groups(texts, names) == expected
