"""0.13 Footprint I: auto-pack, tidy gc, ``tine du``, safe prune, reflog expiry."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest

from opentine import Recorder, TraceEvent, cli
from opentine.kernel import KernelError, validate_links
from opentine.repository import Repo, _paths
from opentine.repository._autopack import maybe_autopack, merge_candidates
from opentine.repository._config import read_config
from opentine.repository._du import usage
from opentine.repository._gc import gc, gc_lock
from opentine.repository._gc_prune import prune
from opentine.repository._gc_tidy import fanout_dirs, loose_entries, old_loose
from opentine.repository._prune_roots import UnsafePlan
from opentine.repository._reflog import read_reflog
from opentine.repository._reflog_expire import expire_reflogs

ROOT = Path(__file__).resolve().parents[1]
OLD = 30 * 86400


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _repo(tmp_path, name="r", compressed=True) -> Repo:
    return Repo.init(tmp_path / name, compression="zlib" if compressed else None)


def _record(repo, ref, steps=4, salt="") -> Recorder:
    rec = Recorder.start(repo, ref=ref, prompt=f"task {ref}{salt}", capture=False)
    for index in range(steps):
        rec.append(
            TraceEvent(
                kind="tool",
                timestamp=index + 1.0,
                trace_id="t",
                span_id=f"s{index}",
                actor="read_file",
                inputs={"path": f"{ref}/{index}{salt}"},
                outputs={"text": f"{ref}{salt} body {index} " * 60},
            )
        )
    return rec


def _age(repo, seconds=OLD) -> None:
    stamp = time.time() - seconds
    for _, path, _ in loose_entries(repo.path):
        os.utime(path, (stamp, stamp))
    for name in os.listdir(repo.path / "packs"):
        os.utime(repo.path / "packs" / name, (stamp, stamp))


def _all_raw(repo) -> dict[str, bytes]:
    return {oid: repo.raw(oid) for oid in repo.iter_oids()}


# -- gc tidies its fan-out directories ------------------------------------------


def test_gc_removes_the_fanout_directories_it_empties_and_old_empty_ones(tmp_path):
    repo = _repo(tmp_path)
    _record(repo, "heads/main").finalize()
    stray = repo.path / "objects" / "blob" / "zz"  # not a fan-out name: untouched
    stray.mkdir(parents=True)
    old_empty = repo.path / "objects" / "event" / "00"
    old_empty.mkdir(parents=True, exist_ok=True)
    before = _all_raw(repo)
    gc(repo)
    assert not list(fanout_dirs(repo.path)) and stray.is_dir()
    assert _all_raw(Repo.open(repo.path)) == before
    _record(repo, "heads/next").finalize()  # writers recreate the directories
    assert Repo.open(repo.path).fsck().ok


def test_a_write_racing_the_fanout_rmdir_retries(tmp_path, monkeypatch):
    target = tmp_path / "objects" / "blob" / "ab" / "cd"
    real = _paths.tempfile.mkstemp
    calls = []

    def racing(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            os.rmdir(target.parent)  # gc emptied and removed it right here
        return real(*args, **kwargs)

    monkeypatch.setattr(_paths.tempfile, "mkstemp", racing)
    _paths.atomic_bytes(target, b"x")
    assert target.read_bytes() == b"x" and len(calls) == 2


# -- auto-pack -------------------------------------------------------------------


def test_autopack_packs_only_cold_objects_once_over_the_threshold(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _record(repo, "heads/a").finalize()
    _age(repo, 120)
    _record(repo, "heads/b", salt="b").finalize()  # young (or re-touched): stays loose
    cold = set(old_loose(repo.path, 60))
    young = {oid for oid, _, _ in loose_entries(repo.path)} - cold
    assert cold and young
    monkeypatch.setenv("OPENTINE_AUTO_PACK", str(len(cold) + 1))
    assert maybe_autopack(repo) is None  # under the threshold
    monkeypatch.setenv("OPENTINE_AUTO_PACK", str(len(cold)))
    before = _all_raw(repo)
    assert maybe_autopack(repo).packed == len(cold)
    assert {oid for oid, _, _ in loose_entries(repo.path)} == young
    assert _all_raw(Repo.open(repo.path)) == before
    assert read_config(repo.path / "config.json")["version"] == 2


def test_autopack_never_upgrades_a_version_1_repository(tmp_path, monkeypatch):
    repo = _repo(tmp_path, compressed=False)
    _record(repo, "heads/a").finalize()
    config = (repo.path / "config.json").read_bytes()
    _age(repo, 120)
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "1")
    assert maybe_autopack(repo) is None
    assert (repo.path / "config.json").read_bytes() == config
    assert not os.listdir(repo.path / "packs")


def test_autopack_can_be_switched_off_and_never_raises(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _record(repo, "heads/a").finalize()
    _age(repo, 120)
    monkeypatch.delenv("OPENTINE_AUTO_PACK")
    config = read_config(repo.path / "config.json")
    _paths.atomic_bytes(
        repo.path / "config.json", json.dumps({**config, "auto_pack": False}).encode()
    )
    assert maybe_autopack(repo) is None
    _paths.atomic_bytes(
        repo.path / "config.json", json.dumps({**config, "auto_pack": {"objects": 1}}).encode()
    )
    with gc_lock(repo.path):  # a gc is running: skipped, not raised
        assert maybe_autopack(repo) is None
    assert maybe_autopack(repo).packed > 0
    assert Repo.open(repo.path).fsck().ok  # 0.12 ignores the extra descriptor key


def test_recorder_finalize_triggers_autopack(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _record(repo, "heads/a").finalize()
    _age(repo, 120)
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "5")
    _record(repo, "heads/b", salt="b").finalize()
    assert any(name.endswith(".tpk") for name in os.listdir(repo.path / "packs"))


def test_small_packs_merge_geometrically():
    assert merge_candidates({str(i): 10 for i in range(8)}) == []
    sizes = {"big": 10_000, **{f"s{i}": 10 + i for i in range(9)}}
    merged = merge_candidates(sizes)
    assert "big" not in merged and len(sizes) - len(merged) + 1 <= 8


# -- tine du ----------------------------------------------------------------------


def test_du_snapshot_of_a_plain_repository(tmp_path):
    repo = _repo(tmp_path, compressed=False)
    _record(repo, "heads/main", steps=2).finalize()
    report = usage(repo, "kind")
    counts = {kind: row["objects"] for kind, row in report["by_kind"].items()}
    assert counts == {"blob": 7, "event": 2, "run": 4}
    assert report["loose"]["objects"] == 13 and report["packed"]["objects"] == 0
    assert all(row["raw_bytes"] == row["stored_bytes"] for row in report["by_kind"].values())
    by_ref = usage(repo, "ref")["by_ref"]
    assert [row["ref"] for row in by_ref] == ["heads/main"] and by_ref[0]["objects"] == 10
    gc(repo)
    packed = usage(Repo.open(repo.path), "run")
    assert packed["loose"] == {
        "empty_fanout_dirs": 0,
        "fanout_dirs": 0,
        "objects": 0,
        "raw_bytes": 0,
        "stored_bytes": 0,
    }
    assert packed["packed"]["objects"] == 13 and packed["by_run"][0]["refs"] == ["heads/main"]


def test_du_cli_json(tmp_path, capsys):
    repo = _repo(tmp_path)
    _record(repo, "heads/main").finalize()
    cli.main(["du", "--repo", str(repo.path), "--by", "ref", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["by_ref"][0]["ref"] == "heads/main" and report["total_bytes"] > 0


# -- prune ------------------------------------------------------------------------


def test_prune_is_a_dry_run_unless_told_to_delete(tmp_path, capsys):
    repo = _repo(tmp_path)
    _record(repo, "heads/main").finalize()
    junk = repo.put("blob", b"abandoned")
    _age(repo)
    before = _all_raw(repo)
    cli.main(["prune", "--repo", str(repo.path), "--json", "--no-git-links"])
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] and dry["candidates"] == 1 and _all_raw(repo) == before
    cli.main(["prune", "--repo", str(repo.path), "--json", "--no-git-links", "--delete"])
    done = json.loads(capsys.readouterr().out)
    assert done["deleted"] == 1 and not repo.has(junk)
    assert Repo.open(repo.path).fsck().ok


def test_prune_keeps_young_and_refreshed_objects(tmp_path):
    repo = _repo(tmp_path)
    young = repo.put("blob", b"just written")
    old_loose = repo.put("blob", b"old but about to be reused")
    old_packed = repo.put("blob", b"old packed, about to be reused")
    gc(repo)
    loose_again = repo.put("blob", b"old but about to be reused, loose")
    _age(repo)
    os.utime(repo._object_path(loose_again))  # fresh again
    repo.put("blob", b"old packed, about to be reused")  # a writer dedups: freshens the pack
    plan = prune(repo, delete=True, min_age=0, git_links=False)  # floor: MIN_GRACE
    assert repo.has(young) and repo.has(old_packed) and repo.has(loose_again)
    assert old_loose in plan.candidates or repo.has(old_loose)


def test_prune_honours_every_root_kind(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    tagged = _record(repo, "heads/t", salt="tag").finalize()
    repo.update_ref("tags/v1", tagged)
    attested = _record(repo, "heads/a", salt="att").finalize()
    repo.attest(attested, {"kind": "evaluation", "scores": {"q": 0.5}}, signer="ci")
    noted = _record(repo, "heads/n", salt="note").finalize()
    shallow = _record(repo, "heads/s", salt="shallow").finalize()
    worktree = _record(repo, "heads/w", salt="wt").finalize()
    logged = _record(repo, "heads/l", salt="log").finalize()
    for name in ("t", "a", "n", "s", "w"):  # drop the head and its history
        (repo.path / "refs" / "heads" / name).unlink()
        (repo.path / "logs" / "heads" / name).unlink()
    (repo.path / "refs" / "heads" / "l").unlink()  # only the reflog remembers it
    from opentine import _git_link
    from opentine.repository import _prune_roots

    # a git checkout whose refs/notes/tine names the run
    monkeypatch.setattr(_prune_roots, "in_git_checkout", lambda worktree: True)

    monkeypatch.setattr(_git_link, "git", lambda *a, **k: f"note\n{noted}\n")
    (repo.path / "shallow").write_text(shallow + "\n")
    (repo.path / "worktrees" / "w1").mkdir(parents=True)
    (repo.path / "worktrees" / "w1" / "HEAD").write_text(worktree + "\n")
    junk = repo.put("blob", b"nobody names me")
    _age(repo)
    prune(repo, delete=True)
    for run in (tagged, attested, noted, shallow, worktree, logged):
        assert len(repo.get(run).payload()["events"]) == 4
    assert not repo.has(junk) and Repo.open(repo.path).fsck().ok


def test_prune_refuses_when_git_links_cannot_be_read(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    from opentine import _git_link
    from opentine.repository import _prune_roots

    monkeypatch.setattr(_prune_roots, "in_git_checkout", lambda worktree: True)

    def broken(*args, **kwargs):
        raise _git_link.GitLinkError("git is not installed")

    monkeypatch.setattr(_git_link, "git", broken)
    with pytest.raises(UnsafePlan):
        prune(repo, delete=True)
    monkeypatch.setattr(_git_link, "git", lambda *a, **k: f"Tine-Run: {repo.put('blob', b'x')}")
    assert prune(repo).unreachable == 0  # the trailer's id is a root


def _expected_reachable(repo) -> set[str]:
    """An independent walk: refs, reflog rows, associations, kernel links."""
    roots = set(repo.list_refs().values())
    for path in (repo.path / "logs").rglob("*"):
        if path.is_file():
            for line in path.read_text().splitlines():
                row = json.loads(line)
                roots.update(v for v in (row["old"], row["new"]) if v)
    roots.update(o for o in repo.iter_oids() if o.split(":")[0] in {"annotation", "attestation"})
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        oid = stack.pop()
        if oid in seen or not repo.has(oid):
            continue
        seen.add(oid)
        stack.extend(validate_links(repo.get(oid)))
    return seen


@pytest.mark.parametrize("seed", range(6))
def test_prune_never_removes_a_reachable_object(tmp_path, seed):
    rng = random.Random(seed)
    repo = _repo(tmp_path)
    junk: list[str] = []
    for index in range(rng.randint(3, 6)):
        rec = _record(repo, f"heads/r{index}", steps=rng.randint(1, 5), salt=f"{seed}")
        run = rec.finalize()
        events = repo.get(run).payload()["events"]
        if rng.random() < 0.5:
            repo.fork(run, rng.choice(events), ref=f"heads/f{index}")
        if rng.random() < 0.3:
            repo.update_ref(f"tags/t{index}", run)
        if rng.random() < 0.3:
            repo.attest(run, {"kind": "evaluation", "scores": {"q": 0.1}}, signer="p")
        if rng.random() < 0.4:  # abandon a branch completely
            (repo.path / "refs" / "heads" / f"r{index}").unlink()
            (repo.path / "logs" / "heads" / f"r{index}").unlink()
        junk.append(repo.put("blob", f"junk {seed} {index}".encode()))
        if rng.random() < 0.4:
            gc(repo)
    expected = _expected_reachable(repo)
    raws = {oid: repo.raw(oid) for oid in expected}
    _age(repo)
    prune(repo, delete=True, git_links=False)
    after = Repo.open(repo.path)
    assert all(after.raw(oid) == raw for oid, raw in raws.items())
    assert not any(after.has(oid) for oid in junk if oid not in expected)
    assert after.fsck().ok


_WRITER = """
import sys
from opentine import Recorder, TraceEvent
from opentine.repository import Repo
repo = Repo.open(sys.argv[1])
rec = Recorder.start(repo, ref="heads/live", prompt="live", capture=False)
for index in range(int(sys.argv[2])):
    rec.append(TraceEvent(kind="tool", timestamp=index + 1.0, trace_id="t",
        span_id=f"s{index}", actor="a", inputs={"i": index},
        outputs={"text": f"live {index} " * 80}))
print(rec.finalize())
"""


def test_autopack_and_prune_racing_a_live_recorder_lose_nothing(tmp_path):
    repo = _repo(tmp_path)
    _record(repo, "heads/old").finalize()
    repo.put("blob", b"old junk")
    _age(repo)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "OPENTINE_AUTO_PACK": "1"}
    writer = subprocess.Popen(
        [sys.executable, "-c", _WRITER, str(repo.path), "120"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    rounds = 0
    while writer.poll() is None or rounds < 2:
        rounds += 1
        try:
            gc(repo, min_age=0)  # harsher than auto-pack: packs even brand-new objects
            prune(repo, delete=True, git_links=False)
        except KernelError as exc:  # the writer's own auto-pack holds the lock
            assert "another tine gc" in str(exc) or "re-touched" in str(exc)
    out, err = writer.communicate(timeout=120)
    assert writer.returncode == 0, err.decode()
    run = out.decode().split()[-1]
    final = Repo.open(repo.path)
    assert final.read_ref("heads/live") == run
    assert len(final.get(run).payload()["events"]) == 120
    assert final.fsck().ok and rounds >= 2


# -- reflog expiry ----------------------------------------------------------------


def _backdate_reflog(repo, ref: str, days: float) -> None:
    path = repo.path / "logs" / Path(ref)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row in rows:
        row["time_ns"] = str(time.time_ns() - int(days * 86400e9))
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_reflog_expiry_is_conservative_and_keeps_the_current_target(tmp_path):
    repo = _repo(tmp_path)
    run = _record(repo, "heads/main", steps=6).finalize()
    _record(repo, "tags/x", steps=1).finalize()
    rows = len(read_reflog(repo.path, "heads/main"))
    _backdate_reflog(repo, "heads/main", 200)
    _backdate_reflog(repo, "tags/x", 200)
    tag_rows = len(read_reflog(repo.path, "tags/x"))
    assert expire_reflogs(repo.path) == 0  # under the default keep of 100 rows
    assert expire_reflogs(repo.path, 30, 0, dry_run=True) == rows - 1
    assert len(read_reflog(repo.path, "heads/main")) == rows
    assert expire_reflogs(repo.path, 30, 0) == rows - 1
    assert [row["new"] for row in read_reflog(repo.path, "heads/main")] == [run]
    assert len(read_reflog(repo.path, "tags/x")) == tag_rows  # tag history never expires
    lock = repo.path / "refs" / "heads" / "main.lock"
    _record(repo, "heads/main", steps=2, salt="again").finalize()
    _backdate_reflog(repo, "heads/main", 200)
    lock.write_text(f"{os.getpid()} host 0\n")  # a live writer holds the ref
    assert expire_reflogs(repo.path, 30, 0) == 0


def _chain(repo):
    leaf = repo.put("blob", b"leaf-data-marker")
    mid = repo.put("blob", f"points at {leaf}".encode())
    (repo.path / "myroot.txt").write_text(mid)  # a root file names only *mid*
    return mid, leaf


def test_prune_refuses_when_a_stored_intermediate_object_is_corrupt(tmp_path):
    repo = Repo.init(tmp_path / "r", compression=None)
    mid, leaf = _chain(repo)
    assert prune(repo, min_age=60, git_links=False).candidates == []
    repo._object_path(mid).write_bytes(b"garbage")
    _age(repo, 86400)
    with pytest.raises(UnsafePlan, match="cannot read stored object"):
        prune(repo, delete=True, min_age=60, git_links=False)
    assert repo._object_path(leaf).exists()


def test_prune_refuses_when_a_pack_codec_is_unavailable(tmp_path, monkeypatch):
    from opentine import _codec
    from opentine.repository._packs import PackSet

    repo = _repo(tmp_path)
    mid, _ = _chain(repo)
    gc(repo)
    leaf_loose = repo.put("blob", b"loose, only reachable through the pack")
    assert not repo._object_path(mid).exists()  # mid is packed now
    _paths.atomic_bytes(repo.path / "myroot.txt", mid.encode())
    _age(repo, 86400)

    def missing(self, digest, number):
        raise _codec.CodecError("zstd is not installed")

    monkeypatch.setattr(PackSet, "block", missing)
    with pytest.raises(UnsafePlan):
        prune(repo, delete=True, min_age=60, git_links=False)
    assert repo._object_path(leaf_loose).exists()


def test_prune_grace_is_above_the_pack_freshen_throttle(tmp_path):
    from opentine.repository._gc_prune import MIN_GRACE
    from opentine.repository._storage import _PACK_FRESHEN

    assert MIN_GRACE > _PACK_FRESHEN
    repo = _repo(tmp_path)
    reused = repo.put("blob", b"unreachable, packed, about to be reused")
    gc(repo)
    _age(repo, 1800)  # touched half an hour ago: the throttle skips a re-touch
    repo.put("blob", b"unreachable, packed, about to be reused")
    plan = prune(repo, delete=True, min_age=864, git_links=False)  # --older-than 0.01
    assert reused not in plan.candidates and repo.has(reused)
