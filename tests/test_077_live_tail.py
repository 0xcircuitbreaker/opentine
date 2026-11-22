"""0.77: ``tine log -f``: the tail engine, its verification statuses and resume cursors."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from opentine import Run, StepKind, _schemas, cli
from opentine._cli_log_follow import follow
from opentine._tail import Follower, check_event, decode_cursor, encode_cursor
from opentine.kernel import ObjectEnvelope
from opentine.repository import Repo


def _repo(tmp_path: Path, steps: int = 3) -> tuple[Repo, Run]:
    repo = Repo.init(tmp_path / "r")
    run = Run(id="live0001")
    for index in range(steps):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    repo.put_run(run, ref="heads/main")
    return repo, run


def _grow(repo: Repo, run: Run, count: int = 1) -> None:
    for _ in range(count):
        run.add_step(StepKind.tool, {"text": "t"}, {"text": "r"})
    repo.put_run(run, ref="heads/main")


def _events(repo: Repo, ref: str = "heads/main") -> list[str]:
    return repo.get(repo.read_ref(ref)).payload()["events"]


def test_a_follower_shows_the_backlog_then_only_new_events_in_order(tmp_path):
    repo, run = _repo(tmp_path)
    follower = Follower(repo, repo.list_refs, names=["heads/main"], backlog=2)
    first = follower.poll()
    assert [r["index"] for r in first] == [1, 2]
    assert all(r["status"] == "verified" and r["verified"] for r in first)
    assert follower.poll() == []
    _grow(repo, run, 2)
    rows = follower.poll()
    assert [r["index"] for r in rows] == [3, 4]
    assert [r["event_id"] for r in rows] == _events(repo)[3:5]
    assert {r["kind"] for r in rows} == {"tool"}
    for item in first + rows:
        assert _schemas.validate(item, "tine-tail-1")[1] == []


def test_the_limit_splits_a_batch_without_losing_or_repeating_events(tmp_path):
    repo, run = _repo(tmp_path, steps=1)
    follower = Follower(repo, repo.list_refs, names=["heads/main"])
    _grow(repo, run, 5)
    seen = []
    for _ in range(4):
        seen += [r["index"] for r in follower.poll(2)]
    assert seen == [1, 2, 3, 4, 5]


def test_an_event_whose_bytes_are_not_readable_is_held_back_not_shown(tmp_path):
    repo, run = _repo(tmp_path, steps=1)
    follower = Follower(repo, repo.list_refs, names=["heads/main"])
    _grow(repo, run, 2)
    held = _events(repo)[1]
    path = repo._object_path(held)
    saved = path.read_bytes()
    path.unlink()
    assert follower.poll() == []  # index 1 is missing: neither it nor index 2 is shown
    path.write_bytes(saved)
    assert [r["index"] for r in follower.poll()] == [1, 2]


class _Store:
    def __init__(self, objects: dict[str, bytes]):
        self.objects = objects

    def raw(self, oid: str) -> bytes:
        return self.objects[oid]

    def _link_exists(self, oid: str) -> bool:
        return oid in self.objects


def test_statuses_never_claim_verified_for_tampered_or_incomplete_events(tmp_path):
    repo, _ = _repo(tmp_path, steps=2)
    second = _events(repo)[1]
    closure = {oid: repo.raw(oid) for oid in repo.iter_oids()}
    assert check_event(_Store(closure), second)[0] == "verified"
    parent = ObjectEnvelope.decode(closure[second], second).payload()["parent_ids"][0]
    partial = {k: v for k, v in closure.items() if k != parent}
    assert check_event(_Store(partial), second)[0] == "unverified"
    tampered = dict(closure)
    tampered[second] = closure[second].replace(b'"kind":"model"', b'"kind":"tool"')
    assert check_event(_Store(tampered), second) == ("invalid", {})
    assert check_event(_Store({}), second) is None


def test_a_rewritten_ref_is_announced_once_and_following_continues(tmp_path):
    repo, run = _repo(tmp_path)
    follower = Follower(repo, repo.list_refs, names=["heads/main"])
    other = Run(id="other001")
    other.add_step(StepKind.model, {"text": "x"}, {"text": "y"})
    stored = repo.put_run(other)
    repo.update_ref("heads/main", stored.run_id, repo.read_ref("heads/main"))
    rows = follower.poll()
    assert [r["type"] for r in rows] == ["rewrite"]
    assert rows[0]["run_id"] == stored.run_id
    assert follower.poll() == []


def test_all_mode_follows_new_refs_from_their_first_event(tmp_path):
    repo, _ = _repo(tmp_path)
    follower = Follower(repo, repo.list_refs, backlog=0)
    extra = Run(id="side0001")
    extra.add_step(StepKind.model, {"text": "a"}, {"text": "b"})
    extra.add_step(StepKind.done, {"text": "c"})
    repo.put_run(extra, ref="experiments/side")
    rows = follower.poll()
    assert [(r["ref"], r["index"]) for r in rows] == [
        ("experiments/side", 0),
        ("experiments/side", 1),
    ]


def test_a_cursor_resumes_exactly_where_it_stopped(tmp_path):
    repo, run = _repo(tmp_path)
    follower = Follower(repo, repo.list_refs, names=["heads/main"], backlog=3)
    assert len(follower.poll()) == 3
    cursor = follower.cursor()
    _grow(repo, run, 2)
    resumed = Follower(repo, repo.list_refs, names=["heads/main"], resume=cursor)
    assert [r["index"] for r in resumed.poll()] == [3, 4]
    assert decode_cursor(encode_cursor({"heads/x": (2, "event:sha256:" + "a" * 64)})) == {
        "heads/x": (2, "a" * 12)
    }


@pytest.mark.parametrize(
    "bad",
    ["", "c1.", "c1.!!!", "x1.AAAA", "c1." + "A" * 20_000, encode_cursor({})[:-2] + "zz"],
)
def test_a_cursor_this_follower_did_not_write_is_refused(bad):
    with pytest.raises(ValueError):
        decode_cursor(bad)


def _args(tmp_path: Path, **extra) -> argparse.Namespace:
    values = {"repo": str(tmp_path / "r"), "ref": None, "all": False, "json": True, "lines": 0}
    values.update(extra)
    return argparse.Namespace(**values)


def test_follow_waits_between_polls_and_prints_events_as_they_land(tmp_path):
    repo, run = _repo(tmp_path, steps=1)
    lines: list[str] = []
    waits: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        _grow(repo, run)  # a writer lands one event while the follower waits

    shown = follow(_args(tmp_path, max_events=3), None, wait=wait, write=lines.append)
    assert shown == 3 and len(waits) == 3
    rows = [json.loads(line) for line in lines]
    assert [r["row"]["index"] for r in rows] == [1, 2, 3]
    for record in rows:
        assert _schemas.detect(record) == "tine-cli-log-follow-1"
        assert _schemas.validate(record, "tine-cli-log-follow-1")[1] == []


def test_log_f_from_the_command_line(tmp_path, monkeypatch, capsys):
    _repo(tmp_path)
    monkeypatch.chdir(tmp_path / "r")
    cli.main(["log", "-f", "main", "--lines", "2", "--max-events", "2"])
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 2 and all(line.endswith("model [verified]") for line in out)
    assert "#1" in out[0] and "#2" in out[1]


@pytest.mark.parametrize(
    "extra",
    [{"interval": 0}, {"lines": -1}, {"max_events": 0}, {"graph": True}],
)
def test_log_f_refuses_bad_options(tmp_path, extra):
    _repo(tmp_path)
    with pytest.raises(ValueError):
        follow(_args(tmp_path, **extra), None, wait=lambda _s: None, write=lambda _l: None)


def test_listing_refs_skips_a_file_renamed_away_by_a_concurrent_writer(tmp_path, monkeypatch):
    from opentine.repository import _paths

    repo, _ = _repo(tmp_path)
    real = _paths.os.walk

    def walk(top, **kwargs):
        for directory, names, files in real(top, **kwargs):
            yield directory, names, [*files, "main.tmp-gone"]  # listed, then renamed away

    monkeypatch.setattr(_paths.os, "walk", walk)
    assert repo.list_refs()["heads/main"] == repo.read_ref("heads/main")
