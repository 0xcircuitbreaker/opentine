"""``tine stats`` — cross-run aggregation over the legacy ``.tine_runs`` index.

Four things are pinned here, and the first is the one that would be a data bug
rather than a display bug if it broke:

1. **Absent, not zero.** ``IndexEntry`` records no tokens and no durations.
   Without ``--deep`` those keys must be *missing* from the payload, so a
   consumer that asks "how many tokens did these runs use?" gets no answer
   instead of the answer "none". Every assertion here is ``not in`` — writing
   ``== 0`` would pass against exactly the bug it is meant to catch.
2. **Filter parity with ``tine ls``.** Both surfaces go through
   ``_query_from_ls_args`` + ``match_entry``, so the same flags must select the
   same runs. The test drives both commands with identical argv and compares
   populations, not literals.
3. **Deterministic group order** — cost descending, then key ascending, so two
   runs of the command diff cleanly and a tie does not reorder on dict order.
4. **Mixed-version aggregation.** A directory holding artifacts written by
   0.3.0, 0.4.0 and 0.5.0 aggregates as one population, and
   ``--group-by format-version`` is the compat-audit view over it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._cli_stats import aggregate, group_rows
from opentine._index_types import IndexEntry

COMPAT = Path(__file__).parent / "fixtures" / "compat"
TOKEN_KEYS = ("total_tokens", "input_tokens", "output_tokens")
DEEP_KEYS = (*TOKEN_KEYS, "duration_total", "duration_mean")

#: 2026-01-01T00:00:00Z and one day later, so ``--group-by day`` is not clock-dependent.
DAY_ONE = 1767225600.0
DAY_TWO = DAY_ONE + 86_400.0


def _make(
    runs_dir: Path,
    name: str,
    *,
    model: str = "mock-model",
    cost: float = 0.25,
    tags: list[str] | None = None,
    created_at: float = DAY_ONE,
    status: RunStatus = RunStatus.completed,
    steps: int = 2,
    tokens: tuple[int, int] = (10, 5),
    duration: float = 1.5,
    prompt: str = "hello",
) -> Run:
    run = Run(
        id=f"stats_{name}",
        model_info=model,
        user_prompt=prompt,
        created_at=created_at,
        tags=tags or [],
    )
    parent = None
    for index in range(steps):
        step = run.add_step(
            StepKind.think,
            {"text": f"{name}-{index}"},
            parent_id=parent,
            cost=cost / steps,
            duration=duration / steps,
            usage={"input": tokens[0] // steps, "output": tokens[1] // steps},
        )
        parent = step.id
    run.status = status
    runs_dir.mkdir(parents=True, exist_ok=True)
    run.save(runs_dir / f"{name}.tine")
    return run


@pytest.fixture
def runs_dir(monkeypatch, tmp_path: Path) -> Path:
    directory = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", directory)
    monkeypatch.chdir(tmp_path)
    directory.mkdir()
    return directory


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _stats(capsys, *argv: str) -> dict:
    code, out = _invoke(capsys, "stats", "--json", *argv)
    assert code == 0, out
    return json.loads(out)


def _entry(**kwargs) -> IndexEntry:
    base = {"file": f"{kwargs.pop('name', 'x')}.tine", "run_id": "r" * 8, "created_at": DAY_ONE}
    return IndexEntry(**{**base, **kwargs})


# --------------------------------------------------------------------------
# 1. absent, not zero
# --------------------------------------------------------------------------


def test_tokens_and_duration_are_absent_without_deep(runs_dir: Path, capsys):
    _make(runs_dir, "a", tags=["alpha"])
    _make(runs_dir, "b", model="other-model", tags=["beta"])
    payload = _stats(capsys, "--group-by", "model")

    assert payload["deep"] is False
    assert "deep_failed" not in payload
    for scope in (payload["totals"], *payload["groups"]):
        for key in DEEP_KEYS:
            # `not in`, never `== 0`: a zero here would read as "these runs were
            # free", which is the failure this test exists to make impossible.
            assert key not in scope, f"{key} must be absent without --deep"
    assert payload["totals"]["runs"] == 2


def test_aggregate_helper_omits_deep_keys_when_not_collected():
    row = aggregate([_entry(name="a", cost=1.0, steps=3)])
    for key in DEEP_KEYS:
        assert key not in row
    assert row["cost_total"] == 1.0
    assert row["steps_total"] == 3


def test_deep_adds_tokens_and_duration(runs_dir: Path, capsys):
    _make(runs_dir, "a", tokens=(10, 4), duration=2.0)
    _make(runs_dir, "b", tokens=(6, 2), duration=1.0)
    payload = _stats(capsys, "--deep", "--group-by", "model")

    totals = payload["totals"]
    assert payload["deep"] is True
    assert payload["deep_failed"] == 0
    assert totals["input_tokens"] == 16
    assert totals["output_tokens"] == 6
    assert totals["total_tokens"] == 22
    assert totals["duration_total"] == pytest.approx(3.0)
    assert totals["duration_mean"] == pytest.approx(1.5)
    assert all(key in payload["groups"][0] for key in DEEP_KEYS)


def test_deep_reports_unloadable_runs_instead_of_counting_them_free(runs_dir: Path, capsys):
    _make(runs_dir, "good", tokens=(8, 2))
    # A file the index accepted at sync time and that then stops loading.
    broken = runs_dir / "broken.tine"
    _make(runs_dir, "broken")
    _stats(capsys)  # index the pair while both are readable
    broken.write_text("{ not json", encoding="utf-8")
    broken.touch()

    payload = _stats(capsys, "--deep")
    assert payload["unreadable"] == 1
    assert payload["deep_failed"] == 0  # the corrupt row never reaches --deep
    assert payload["totals"]["runs"] == 1
    assert payload["totals"]["total_tokens"] == 10


# --------------------------------------------------------------------------
# 2. scope
# --------------------------------------------------------------------------


def test_scope_is_stated_in_json_and_help(runs_dir: Path, capsys):
    payload = _stats(capsys)
    assert payload["command"] == "stats"
    assert payload["scope"] == "legacy-index"
    assert ".tine_runs" in payload["scope_note"]
    assert "not v3 repositories" in payload["scope_note"]
    assert "0.7.0" in payload["scope_note"]

    code, out = _invoke(capsys, "stats", "--help")
    assert code == 0
    assert "legacy .tine_runs file index only" in " ".join(out.split())


def test_human_rendering_repeats_the_scope(runs_dir: Path, capsys):
    _make(runs_dir, "a")
    code, out = _invoke(capsys, "stats")
    assert code == 0
    assert "not v3 repositories" in " ".join(out.split())
    assert "1 run(s)" in out


def test_human_rendering_shows_deep_columns_only_under_deep(runs_dir: Path, capsys):
    _make(runs_dir, "a", tokens=(10, 4), duration=2.0)
    code, plain = _invoke(capsys, "stats", "--group-by", "model")
    assert code == 0 and "Tokens" not in plain and "tokens=" not in plain
    code, deep = _invoke(capsys, "stats", "--deep", "--group-by", "model")
    assert code == 0
    assert "Tokens" in deep and "tokens=14" in deep


def test_empty_index_is_a_zero_run_aggregate_not_an_error(runs_dir: Path, capsys):
    payload = _stats(capsys)
    assert payload["totals"]["runs"] == 0
    assert payload["totals"]["cost_total"] == 0.0
    assert payload["totals"]["first_created_at"] is None
    assert payload["groups"] == []
    for key in DEEP_KEYS:
        assert key not in payload["totals"]


# --------------------------------------------------------------------------
# 3. filter parity with `tine ls`
# --------------------------------------------------------------------------


FILTERS = [
    [],
    ["--tag", "alpha"],
    ["--model", "other-model"],
    ["--status", "failed"],
    ["--cost-min", "0.3"],
    ["--cost-max", "0.3"],
    ["--grep", "needle"],
    ["--since", "2026-01-01", "--until", "2026-01-03"],
    ["--tag", "alpha", "--model", "mock-model"],
]


@pytest.fixture
def population(runs_dir: Path) -> Path:
    _make(runs_dir, "a", tags=["alpha"], cost=0.10)
    _make(runs_dir, "b", tags=["alpha", "beta"], cost=0.40, model="other-model")
    _make(runs_dir, "c", tags=[], cost=0.50, status=RunStatus.failed, created_at=DAY_TWO)
    _make(runs_dir, "d", tags=["beta"], cost=0.20, prompt="needle in a haystack")
    return runs_dir


@pytest.mark.parametrize("flags", FILTERS, ids=lambda flags: "+".join(flags) or "none")
def test_filter_parity_with_ls(population: Path, capsys, flags: list[str]):
    code, out = _invoke(capsys, "ls", "--json", "--limit", "500", *flags)
    assert code == 0, out
    listed = [row for row in json.loads(out)["runs"] if not row["unreadable"]]
    payload = _stats(capsys, *flags)

    assert payload["totals"]["runs"] == len(listed)
    assert payload["totals"]["cost_total"] == pytest.approx(sum(row["cost"] for row in listed))
    assert payload["totals"]["steps_total"] == sum(row["steps"] for row in listed)
    assert payload["totals"]["models"] == sorted({row["model"] for row in listed})


def test_bad_filter_exits_one_without_json(population: Path, capsys):
    code, out = _invoke(capsys, "stats", "--json", "--since", "not-a-date")
    assert code == 1
    assert "Bad filter" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_unreadable_rows_are_reported_separately(runs_dir: Path, capsys):
    _make(runs_dir, "a", cost=0.25)
    (runs_dir / "corrupt.tine").write_text("{not json", encoding="utf-8")

    payload = _stats(capsys)
    assert payload["totals"]["runs"] == 1
    assert payload["unreadable"] == 1
    assert payload["totals"]["cost_total"] == pytest.approx(0.25)


def test_index_sync_side_effect_matches_ls(runs_dir: Path, tmp_path: Path, capsys, monkeypatch):
    _make(runs_dir, "a")
    _make(runs_dir, "b", model="other-model")
    index = runs_dir / "index.json"

    _invoke(capsys, "ls", "--json")
    from_ls = json.loads(index.read_text(encoding="utf-8"))["entries"]
    index.unlink()
    _stats(capsys)
    from_stats = json.loads(index.read_text(encoding="utf-8"))["entries"]

    assert from_stats == from_ls


# --------------------------------------------------------------------------
# 4. grouping
# --------------------------------------------------------------------------


def test_groups_are_ordered_by_cost_desc_then_key_asc(runs_dir: Path, capsys):
    _make(runs_dir, "cheap", model="zeta", cost=0.10)
    _make(runs_dir, "tie_b", model="beta", cost=0.50)
    _make(runs_dir, "tie_a", model="alpha", cost=0.50)
    _make(runs_dir, "rich", model="gamma", cost=0.90)

    keys = [row["key"] for row in _stats(capsys, "--group-by", "model")["groups"]]
    # gamma outspends both ties; the tie breaks on key, not on insertion order.
    assert keys == ["gamma", "alpha", "beta", "zeta"]


def test_group_order_is_stable_across_invocations(population: Path, capsys):
    first = _stats(capsys, "--group-by", "tag")["groups"]
    second = _stats(capsys, "--group-by", "tag")["groups"]
    assert [row["key"] for row in first] == [row["key"] for row in second]


def test_group_by_tag_counts_each_tag_and_names_the_untagged(population: Path, capsys):
    groups = {row["key"]: row for row in _stats(capsys, "--group-by", "tag")["groups"]}
    assert groups["alpha"]["runs"] == 2
    assert groups["beta"]["runs"] == 2
    assert groups["(untagged)"]["runs"] == 1
    # A run with two tags is counted under both, so groups need not sum to runs.
    assert sum(row["runs"] for row in groups.values()) == 5


def test_group_by_day_and_status(population: Path, capsys):
    days = {row["key"]: row["runs"] for row in _stats(capsys, "--group-by", "day")["groups"]}
    assert days == {"2026-01-01": 3, "2026-01-02": 1}
    statuses = {row["key"]: row["runs"] for row in _stats(capsys, "--group-by", "status")["groups"]}
    assert statuses == {"completed": 3, "failed": 1}


def test_limit_caps_the_group_list(population: Path, capsys):
    assert len(_stats(capsys, "--group-by", "tag", "--limit", "1")["groups"]) == 1
    assert len(_stats(capsys, "--group-by", "tag", "--limit", "0")["groups"]) == 3


def test_group_rows_histogram_spans_format_versions():
    """The audit view: one bucket per version, over rows that really differ."""
    entries = [
        _entry(name="one", format_version=1, cost=0.10),
        _entry(name="two", format_version=2, cost=0.30),
        _entry(name="three", format_version=2, cost=0.30),
        _entry(name="four", format_version=3, cost=0.05),
    ]
    rows = group_rows(entries, "format-version", None, 0)
    assert [row["key"] for row in rows] == ["2", "1", "3"]
    assert aggregate(entries)["format_versions"] == {"1": 1, "2": 2, "3": 1}
    for row in rows:
        for key in DEEP_KEYS:
            assert key not in row


# --------------------------------------------------------------------------
# 5. mixed-version compat audit
# --------------------------------------------------------------------------


def test_stats_over_a_mixed_release_runs_directory(runs_dir: Path, capsys):
    """Artifacts written by three published releases aggregate as one population."""
    releases = sorted(path for path in COMPAT.iterdir() if path.is_dir())
    assert [path.name for path in releases] == ["v0_3_0", "v0_4_0", "v0_5_0"]
    copied = 0
    for release in releases:
        for artifact in sorted(release.glob("*.tine")):
            shutil.copyfile(artifact, runs_dir / f"{release.name}-{artifact.name}")
            copied += 1

    payload = _stats(capsys, "--group-by", "format-version")
    assert payload["unreadable"] == 0
    assert payload["totals"]["runs"] == copied
    histogram = payload["totals"]["format_versions"]
    assert sum(histogram.values()) == copied
    assert sum(row["runs"] for row in payload["groups"]) == copied
    assert {row["key"] for row in payload["groups"]} == set(histogram)

    deep = _stats(capsys, "--deep")
    assert deep["deep_failed"] == 0
    assert deep["totals"]["runs"] == copied
    assert deep["totals"]["total_tokens"] >= 0
    assert "total_tokens" in deep["totals"]
