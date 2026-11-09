"""0.47 (F2): the merge queue on ``coord/`` leases, its fencing and a kill -9 chaos test.

Landing is one compare-and-swap of the queue record, so an entry lands at most
once whatever happens to the workers: the chaos test kills workers mid-land
(``Popen.kill``: SIGKILL on POSIX, TerminateProcess on Windows) and then
proves every run landed exactly once, under strictly increasing fencing
tokens, with a verifying attestation each.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _merge_record, _schemas, cli
from opentine.coord import _merge_queue as queue
from opentine.coord._tasks import LeaseError
from opentine.kernel import canonical_json
from opentine.repository import Repo

ROOT = Path(__file__).resolve().parents[1]
KEY = b"\x0b" * 32


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEY)


def _event(repo: Repo, text: str, *parents: str) -> str:
    payload = {
        "causal_ids": [],
        "kind": "think",
        "parent_ids": list(parents),
        "time_unix": 1,
        "output_blob": repo.put("blob", canonical_json({"t": text}), redact=False),
    }
    return repo.put("event", payload, redact=False)  # fmt: skip


def _repo(path: Path, workers: int) -> tuple[Repo, list[str]]:
    """``heads/main`` holds one base run; *workers* forks each add one event."""
    repo = Repo.init(path)
    root = _event(repo, "base")
    base = repo.put("run", {"events": [root], "manifests": {}, "roots": [root], "tips": [root]})
    repo.update_ref("heads/main", base)
    runs = []
    for n in range(workers):
        tip = _event(repo, f"worker {n}", root)
        runs.append(repo.put("run", {"events": [root, tip], "manifests": {}, "roots": [root],
                                     "tips": [tip], "forked_from": base}))  # fmt: skip
    return repo, runs


def test_claim_land_and_fencing(tmp_path):
    repo, runs = _repo(tmp_path / "r", 3)
    queue.init(repo, "main", "heads/main")
    for run in runs:
        queue.enqueue(repo, "main", run, "ci")
    with pytest.raises(LeaseError) as again:
        queue.enqueue(repo, "main", runs[0], "ci")
    assert again.value.code == "exists"
    first = queue.claim(repo, "main", "w1", 30)
    with pytest.raises(LeaseError) as held:
        queue.claim(repo, "main", "w2", 30)
    assert held.value.code == "held"
    with pytest.raises(LeaseError) as stale:
        queue.land(repo, "main", "w1", first["fencing"] - 1, key=_key())
    assert stale.value.code == "stale"
    landed = queue.land(repo, "main", "w1", first["fencing"], key=_key())
    assert landed["status"] == "landed" and landed["attestation"] is not None
    with pytest.raises(LeaseError):  # the lease was released with the landing
        queue.land(repo, "main", "w1", first["fencing"], key=_key())
    second = queue.claim(repo, "main", "w2", 30)
    assert second["fencing"] == first["fencing"] + 1
    result = queue.land(repo, "main", "w2", second["fencing"], key=_key())
    value = queue.get(repo, "main")
    assert repo.read_ref("heads/main") == value["head"] == result["merge"]
    record = json.loads(repo.get(result["attestation"]).body)
    assert _schemas.validate(record) == ("opentine-merge-1", [])
    found = _merge_record.check(record, run=repo.get(result["merge"]).payload())
    assert found["fencing"] == second["fencing"] and found["target"] == "heads/main"
    assert repo.fsck().ok


def test_a_target_moved_outside_the_queue_is_never_overwritten(tmp_path):
    repo, runs = _repo(tmp_path / "r", 2)
    queue.init(repo, "main", "heads/main")
    queue.enqueue(repo, "main", runs[0], "ci")
    repo.update_ref("heads/main", runs[1])  # a direct push, not through the queue
    held = queue.claim(repo, "main", "w1", 30)
    assert repo.read_ref("heads/main") == runs[1]
    with pytest.raises(LeaseError) as diverged:
        queue.land(repo, "main", "w1", held["fencing"], key=_key())
    assert diverged.value.code == "diverged"
    assert repo.read_ref("heads/main") == runs[1]


def test_an_expired_lease_is_taken_over_and_its_holder_fenced_off(tmp_path, monkeypatch):
    repo, runs = _repo(tmp_path / "r", 1)
    queue.init(repo, "main", "heads/main")
    queue.enqueue(repo, "main", runs[0], "ci")
    clock = [1_000_000]
    monkeypatch.setattr("opentine.coord._merge_queue.now_ms", lambda: clock[0])
    slow = queue.claim(repo, "main", "slow", 1)
    clock[0] += 5_000
    fast = queue.claim(repo, "main", "fast", 1)
    assert fast["fencing"] == slow["fencing"] + 1
    with pytest.raises(LeaseError) as stale:
        queue.land(repo, "main", "slow", slow["fencing"], key=_key())
    assert stale.value.code == "stale"
    assert queue.land(repo, "main", "fast", fast["fencing"], key=_key())["status"] == "landed"


def test_a_failed_gate_rejects_the_entry_and_the_queue_moves_on(tmp_path):
    repo, runs = _repo(tmp_path / "r", 2)
    alice = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    gates = {
        "format": "opentine-merge-gates/1",
        "approvals": {"required": 1, "keys": [alice.public_key().public_bytes_raw().hex()]},
    }
    queue.init(repo, "main", "heads/main", gates)  # fmt: skip
    for run in runs:
        queue.enqueue(repo, "main", run, "ci")
    approval = _merge_record.sign_approval(
        _merge_record.build_approval(runs[1], "heads/main", "alice"), alice, algorithm="ed25519"
    )
    evidence = {"approvals": [approval]}
    token = queue.claim(repo, "main", "w", 30)["fencing"]
    out = queue.land(repo, "main", "w", token, evidence=evidence, key=_key())
    assert out["status"] == "rejected" and out["reason"].startswith("gates: approval")
    token = queue.claim(repo, "main", "w", 30)["fencing"]
    out = queue.land(repo, "main", "w", token, evidence=evidence, key=_key())
    assert out["status"] == "landed" and out["gates"][0]["gate"] == "approval"
    record = json.loads(repo.get(out["attestation"]).body) if out["attestation"] else None
    assert record is None or record["gates"] == out["gates"]
    value = queue.get(repo, "main")
    assert [r["run"] for r in value["rejected"]] == [runs[0]]
    assert [r["run"] for r in value["landed"]] == [runs[1]]


def _tine(monkeypatch, capsys, *argv: str) -> tuple[int, dict]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv, "--json"])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, json.loads(capsys.readouterr().out)


def test_the_cli_drives_a_queue(monkeypatch, capsys, tmp_path):
    repo, runs = _repo(tmp_path / "r", 2)
    path = (tmp_path / "r").as_posix()
    key = tmp_path / "k.key"
    key.write_text(KEY.hex(), encoding="utf-8")
    steps = [("merge-queue", "init", "q", "--target", "heads/main"),
             *(("merge-queue", "add", "q", run) for run in runs),
             ("merge-queue", "claim", "q", "--holder", "w1"),
             ("merge-queue", "land", "q", "--holder", "w1", "--fencing", "1",
              "--ed25519-key-file", key.as_posix()),
             ("merge-queue", "work", "q", "--holder", "w2", "--ed25519-key-file", key.as_posix()),
             ("merge-queue", "show", "q")]  # fmt: skip
    for argv in steps:
        code, body = _tine(monkeypatch, capsys, *argv, "--repo", path)
        assert code == 0, body
        assert _schemas.validate_output(body) == [], body
    assert len(body["queue"]["landed"]) == 2 and body["queue"]["entries"] == []
    oid = body["queue"]["landed"][-1]["attestation"]
    code, body = _tine(monkeypatch, capsys, "merge-queue", "verify", oid, "--run", "--public-key",
                       _key().public_key().public_bytes_raw().hex(), "--repo", path)  # fmt: skip
    assert code == 0 and body["result"]["state"] == "verified"
    code, body = _tine(monkeypatch, capsys, "merge-queue", "verify", oid, "--public-key",
                       "00" * 32, "--repo", path)  # fmt: skip
    assert code == 4
    code, body = _tine(monkeypatch, capsys, "merge-queue", "land", "q", "--holder", "w1",
                       "--fencing", "1", "--ed25519-key-file", key.as_posix(),
                       "--repo", path)  # fmt: skip
    assert code == 1 and "stale" in body["error"]["message"]


WORKER = """
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentine.coord import _merge_queue as q
from opentine.coord._tasks import LeaseError
from opentine.repository import Repo

repo, holder = Repo.open(sys.argv[1]), sys.argv[2]
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[3]))
deadline = time.monotonic() + float(sys.argv[4])
last = None
while True:
    if time.monotonic() > deadline:  # fail fast, with what wedged the queue
        print(f"{holder}: queue not drained in time; last refusal: {last!r}", file=sys.stderr)
        print(q.get(repo, "main"), file=sys.stderr)
        for path in sorted(Path(repo.path).rglob("*lock")):
            print(path, path.read_bytes()[:200], file=sys.stderr)
        sys.exit(3)
    try:
        token = q.claim(repo, "main", holder, 2.0)["fencing"]
    except LeaseError as exc:
        if exc.code == "empty":
            break
        last = exc
        time.sleep(0.01)
        continue
    try:
        q.land(repo, "main", holder, token, key=key)
    except LeaseError as exc:
        if exc.code not in ("stale", "contended"):
            raise
        last = exc
"""
WORKER_SECONDS = 120.0


def _spawn(path: Path, holder: str) -> subprocess.Popen:
    # stderr goes to a file, never a pipe nobody reads until the end: a worker
    # printing a traceback larger than the pipe buffer (4 KiB on Windows) would
    # block in exit forever and turn any failure into a hang.
    log = open(path.parent / f"{holder}.stderr", "wb")  # noqa: SIM115 - closed by _stderr
    argv = [sys.executable, "-c", WORKER, path.as_posix(), holder, KEY.hex(), str(WORKER_SECONDS)]
    proc = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=log)
    proc.log = log  # type: ignore[attr-defined]
    return proc


def _stderr(proc: subprocess.Popen) -> str:
    proc.log.close()  # type: ignore[attr-defined]
    return Path(proc.log.name).read_text(errors="replace")  # type: ignore[attr-defined]


def test_a_writer_killed_before_its_replace_never_wedges_the_queue(tmp_path):
    """The crash window behind the Windows chaos hang: a writer killed after
    creating a ref's ``<ref>..lock`` staging file and before replacing the ref
    (its fsync is slow on Windows) left it behind, and ``O_EXCL`` on it then
    failed every later write of that ref, wedging the queue for good."""
    repo, runs = _repo(tmp_path / "r", 2)
    queue.init(repo, "main", "heads/main")
    for run in runs:
        queue.enqueue(repo, "main", run, "ci")
    refs = Path(repo.path) / "refs"
    for ref in ("heads/main", "coord/merge-queue/main"):  # both refs a landing moves
        (refs / f"{ref}..lock").write_bytes(b"0" * 10)  # torn: killed mid-write
    first = queue.claim(repo, "main", "w1", 2.0)  # the killed holder's lease, never landed
    for ref in ("heads/main", "coord/merge-queue/main"):
        (refs / f"{ref}..lock").write_bytes(b"")
    with pytest.raises(LeaseError) as held:
        queue.claim(repo, "main", "w2", 30)
    assert held.value.code == "held"
    later = first["lease_expires_ms"] + 1
    with pytest.MonkeyPatch.context() as patch:  # the dead holder's lease runs out
        patch.setattr(queue, "now_ms", lambda: later)
        second = queue.claim(repo, "main", "w2", 30)
        assert second["fencing"] == first["fencing"] + 1
        assert queue.land(repo, "main", "w2", second["fencing"], key=_key())["status"] == "landed"
        (refs / "heads/main..lock").write_bytes(b"")  # and again, after a landing
        token = queue.claim(repo, "main", "w3", 30)["fencing"]
        assert queue.land(repo, "main", "w3", token, key=_key())["status"] == "landed"
    value = queue.get(repo, "main")
    assert value["entries"] == [] and repo.read_ref("heads/main") == value["head"]
    assert not list(refs.rglob("*..lock"))
    assert repo.fsck().ok


def test_kill_9_workers_never_double_merge(tmp_path):
    entries = 16
    repo, runs = _repo(tmp_path / "r", entries)
    base = repo.read_ref("heads/main")
    queue.init(repo, "main", "heads/main")
    for run in runs:
        queue.enqueue(repo, "main", run, "ci")
    chance = random.Random(47)
    workers = {f"w{n}": _spawn(tmp_path / "r", f"w{n}") for n in range(4)}
    spawned, killed = len(workers), 0
    # A generous bound on the loop, never a timing assertion: the queue drains
    # because a killed holder's lease expires and a live worker takes it over.
    for _ in range(600):
        if not queue.get(repo, "main")["entries"]:
            break
        time.sleep(chance.uniform(0.05, 0.3))
        name = chance.choice(sorted(workers))
        if killed < 6 and workers[name].poll() is None:
            workers[name].kill()  # SIGKILL / TerminateProcess: no cleanup runs
            workers[name].wait()
            killed += 1
        if workers[name].poll() is not None:
            spawned += 1
            _stderr(workers[name])  # closes its log
            workers[f"w{spawned}"] = _spawn(tmp_path / "r", f"w{spawned}")
            del workers[name]
    # Bounded in total: each worker gives up on its own after WORKER_SECONDS
    # (printing the queue and any lock files), so a wedge fails in minutes.
    ends = time.monotonic() + WORKER_SECONDS + 60
    for proc in workers.values():
        try:
            proc.wait(timeout=max(1.0, ends - time.monotonic()))
        except subprocess.TimeoutExpired:
            for other in workers.values():
                other.kill()
                other.wait()
            pytest.fail("a worker did not exit:\n" + "\n".join(map(_stderr, workers.values())))
        assert proc.returncode == 0, _stderr(proc)
    value = queue.get(repo, "main")
    assert value["entries"] == [] and value["rejected"] == [] and killed > 0
    landed = [row["run"] for row in value["landed"]]
    assert sorted(landed) == sorted(runs)  # each exactly once
    fencing = [row["fencing"] for row in value["landed"]]
    assert fencing == sorted(set(fencing))  # strictly increasing tokens
    # The mainline: walking parents[0] from the head meets each run merged in once.
    merged_in, oid = [], value["head"]
    while oid != base:
        ours, theirs = repo.get(oid).payload()["parents"]
        merged_in.append(theirs)
        oid = ours
    assert sorted(merged_in) == sorted(runs)
    assert repo.read_ref("heads/main") == value["head"]
    for row in value["landed"]:
        if row["attestation"]:
            record = json.loads(repo.get(row["attestation"]).body)
            found = _merge_record.check(record, public_key=_key().public_key().public_bytes_raw())
            assert found["fencing"] == row["fencing"] and found["run"] == row["merge"]
    assert repo.fsck().ok
