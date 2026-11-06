"""0.36 ``opentine-log/1``: the op log, ``tine op log|verify`` and ``tine undo``."""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from opentine import Run, StepKind, cli
from opentine.repository import Repo, _tlog, _tlog_note
from opentine.repository._oplog import ORIGIN, log_root, read_ops


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    store = Repo.init(tmp_path)
    run = Run(id="base0001", model_info="m")
    for index in range(3):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    store.put_run(run, ref="heads/main")  # a library write: not logged
    return store


def _json(capsys, argv: list[str]) -> dict:
    capsys.readouterr()
    cli.main([*argv, "--json"])
    return json.loads(capsys.readouterr().out)


def _fails(capsys, argv: list[str]) -> dict:
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main([*argv, "--json"])
    assert exc.value.code == 1
    return json.loads(capsys.readouterr().out)


def _refs(repo: Repo) -> dict[str, str]:
    return repo.list_refs()


@pytest.mark.parametrize(
    "argv",
    [
        ["branch", "feature"],
        ["tag", "v1"],
        ["fork", "heads/main", "--from-step", "1", "--ref", "experiments/f1"],
        ["reset", "heads/main", "@second"],
        ["branch", "-d", "gone"],
        ["tag", "-d", "old"],
    ],
)
def test_undo_round_trips_every_ref_moving_command(repo, capsys, argv):
    second = repo.put_run(Run(id="second01", model_info="m")).run_id
    cli.main(["branch", "gone"])
    cli.main(["tag", "old"])
    argv = [second if a == "@second" else a for a in argv]
    before = _refs(repo)
    cli.main(argv)
    after = _refs(repo)
    assert after != before
    op = _json(capsys, ["op", "log"])["ops"][0]
    assert op["command"] == argv[0] and op["format"] == "opentine-op/1"
    assert all(row["new"] == after.get(row["ref"]) for row in op["refs"])
    result = _json(capsys, ["undo"])
    assert result["undone"] == op["id"] and _refs(repo) == before
    # Undo is itself a logged forward op: undoing it redoes the command.
    latest = _json(capsys, ["op", "log"])["ops"][0]
    assert latest["command"] == "undo" and latest["undoes"] == op["id"]
    _json(capsys, ["undo"])
    assert _refs(repo) == after


def test_undo_by_id_refuses_a_superseded_op_unless_forced(repo, capsys):
    cli.main(["branch", "feature"])
    first = _json(capsys, ["op", "log"])["ops"][0]["id"]
    other = repo.put_run(Run(id="other001", model_info="m")).run_id
    cli.main(["reset", "heads/feature", other])
    refused = _fails(capsys, ["undo", first[:6]])
    assert refused["problems"][0]["kind"] == "superseded"
    _json(capsys, ["undo", first, "--force"])
    assert repo.read_ref("heads/feature") is None


def test_undo_detects_a_gap_left_by_a_writer_that_does_not_log(repo, capsys):
    cli.main(["branch", "feature"])
    old_writer = repo.put_run(Run(id="legacy01", model_info="m")).run_id
    repo.update_ref("heads/feature", old_writer)  # as opentine 0.34 would: no op log
    refused = _fails(capsys, ["undo"])
    assert refused["problems"] == [
        {
            "kind": "gap",
            "ref": "heads/feature",
            "logged": repo.read_ref("heads/main"),
            "current": old_writer,
        }
    ]
    assert repo.read_ref("heads/feature") == old_writer  # nothing moved
    _json(capsys, ["undo", "--force"])
    assert repo.read_ref("heads/feature") is None


def test_gap_is_found_even_when_the_unlogged_writer_put_the_ref_back(repo, capsys):
    cli.main(["branch", "feature"])
    main = repo.read_ref("heads/main")
    other = repo.put_run(Run(id="aba00001", model_info="m")).run_id
    repo.update_ref("heads/feature", other)
    repo.update_ref("heads/feature", main)  # same value again; the reflog shows it
    assert _fails(capsys, ["undo"])["problems"][0]["kind"] == "gap"


def test_undo_with_an_empty_log_refuses(repo, capsys):
    assert "empty" in _fails(capsys, ["undo"])["error"]["message"]


def test_log_is_tlog_tiles_with_a_signed_checkpoint(repo, capsys):
    cli.main(["branch", "a"])
    cli.main(["branch", "b"])
    root = log_root(repo.path)
    assert root == repo.path / "log" / "op"
    note = (root / "checkpoint").read_bytes().decode()
    origin, size, encoded, blank, signature = note.split("\n")[:5]
    assert (origin, size, blank) == (ORIGIN, "2", "")
    assert signature.startswith(f"— {ORIGIN} ")
    entries = _tlog.unbundle((root / "tile/entries/000.p/2").read_bytes(), 2)
    leaves = [_tlog.leaf_hash(e) for e in entries]
    assert (root / "tile/0/000.p/2").read_bytes() == b"".join(leaves)
    import base64

    assert base64.b64decode(encoded) == _tlog.merkle_root(leaves)
    assert json.loads(entries[1])["prev"] == leaves[0].hex()
    report = _json(capsys, ["op", "verify"])
    assert report["ok"] and report["size"] == 2


def test_merkle_and_tile_paths_follow_rfc6962_and_c2sp():
    assert _tlog.merkle_root([]) == hashlib.sha256(b"").digest()
    assert _tlog.leaf_hash(b"").hex().startswith("6e340b9c")
    assert _tlog.tile_path(0, 1234067) == "tile/0/x001/x234/067"
    assert _tlog.tile_path("entries", 7, 3) == "tile/entries/007.p/3"
    three = [_tlog.leaf_hash(bytes([i])) for i in range(3)]
    ab = _tlog._node(three[0], three[1])
    assert _tlog.merkle_root(three) == _tlog._node(ab, three[2])


def test_a_log_past_one_tile_writes_full_and_higher_level_tiles(tmp_path):
    root = tmp_path / "log"
    for index in range(258):
        _tlog_note.append(root, "example/log", lambda _e, i=index: f"e{i}".encode())
    entries = _tlog_note.verify_log(root, "example/log")
    assert entries[257] == b"e257" and len(entries) == 258
    assert (root / "tile/entries/000").exists() and (root / "tile/entries/001.p/2").exists()
    assert len((root / "tile/0/000").read_bytes()) == 256 * 32
    assert (root / "tile/1/000.p/1").read_bytes() == _tlog.merkle_root(
        [_tlog.leaf_hash(e) for e in entries[:256]]
    )


@pytest.mark.parametrize("target", ["entries", "hashes", "checkpoint", "size"])
def test_tampering_is_detected(repo, capsys, target):
    cli.main(["branch", "a"])
    cli.main(["branch", "b"])
    root = log_root(repo.path)
    if target == "entries":
        path = root / "tile/entries/000.p/2"
        path.write_bytes(path.read_bytes().replace(b"heads/b", b"heads/c"))
    elif target == "hashes":
        path = root / "tile/0/000.p/2"
        path.write_bytes(b"\x00" * 64)
    else:
        path = root / "checkpoint"
        old = b"\n2\n" if target == "size" else b"op\n"
        path.write_bytes(path.read_bytes().replace(old, b"\n1\n" if target == "size" else b"oq\n"))
    with pytest.raises(_tlog.LogError):
        read_ops(repo.path)
    assert _fails(capsys, ["op", "verify"])["error"]
    assert _fails(capsys, ["undo"])["error"]["message"]
    # A command still moves its ref: only the log append is refused (and warned).
    cli.main(["branch", "c"])
    assert repo.read_ref("heads/c") is not None


def test_verify_pins_a_key_and_never_touches_the_network(repo, capsys, monkeypatch, tmp_path):
    cli.main(["branch", "a"])
    vkey = (log_root(repo.path) / "vkey").read_text().strip()

    def no_network(*_a, **_k):
        raise AssertionError("op verify touched the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    assert _json(capsys, ["op", "verify", "--vkey", vkey])["pinned"] is True
    other = tmp_path / "other"
    _tlog_note.append(other, ORIGIN, lambda _e: b"x")
    foreign = (other / "vkey").read_text().strip()
    assert "signature" in _fails(capsys, ["op", "verify", "--vkey", foreign])["error"]["message"]


def test_gap_is_found_when_the_clock_does_not_tick(repo, capsys, monkeypatch):
    # Windows clocks can stamp an unlogged write in the same tick as the op.
    import time

    monkeypatch.setattr(time, "time_ns", lambda: 1_700_000_000_000_000_000)
    cli.main(["branch", "feature"])
    main = repo.read_ref("heads/main")
    other = repo.put_run(Run(id="tick0001", model_info="m")).run_id
    repo.update_ref("heads/feature", other)
    repo.update_ref("heads/feature", main)
    assert _fails(capsys, ["undo"])["problems"][0]["kind"] == "gap"


def test_an_index_selector_wins_over_an_id_prefix(repo, capsys):
    cli.main(["branch", "a"])
    cli.main(["branch", "b"])
    ops = read_ops(repo.path)
    result = _json(capsys, ["undo", "0", "--force"])
    assert result["undone"] == ops[0]["id"]
