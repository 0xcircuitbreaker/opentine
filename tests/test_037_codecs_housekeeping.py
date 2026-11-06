"""0.37 codecs and housekeeping: xz, --archival, --level, temp reaping, F_FULLFSYNC, fsck budget."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
import types

import pytest

from opentine import Run, _canon, _codec
from opentine.cli import main
from opentine.graph import StepKind
from opentine.repository import Repo, _autopack
from opentine.repository import _gc as gc_module
from opentine.repository._archive import create_archive
from opentine.repository._gc import gc
from opentine.repository._reap import is_staging

_XZ = pytest.mark.skipif(not _codec.available("xz"), reason="Python built without lzma")


@pytest.fixture
def compress_on(monkeypatch):
    monkeypatch.setenv("OPENTINE_COMPRESS", "1")


def _run(steps: int = 12) -> Run:
    run = Run(id="housekeeping")
    for index in range(steps):
        run.add_step(
            StepKind.tool,
            {"name": "Bash", "arguments": {"command": f"ls -la /srv/project/{index} " * 20}},
            outputs={"result": "total 48\ndrwxr-xr-x  2 user user 4096 file.txt\n" * 40},
        )
    run.add_step(StepKind.done, {"text": "finished"})
    return run


# -- codec 4: xz ----------------------------------------------------------------


@_XZ
def test_xz_is_codec_4_and_round_trips():
    raw = b'{"hello": "world"}\n' * 400
    stored = _codec.wrap(raw, "xz")
    assert stored is not None and stored[len(_codec.MAGIC)] == 4 == _codec.XZ
    assert _codec.unwrap(stored, limit=len(raw)) == raw


@_XZ
def test_xz_decoding_is_bounded_and_strict():
    raw = os.urandom(64) * 64
    frame = _codec.compress_frame(raw, "xz")
    header = _codec.MAGIC + bytes([_codec.XZ])

    def body(size: int, data: bytes) -> bytes:
        return header + _codec._uvarint(size) + data

    with pytest.raises(_codec.CodecError, match="allows"):
        _codec.unwrap(body(len(raw), frame), limit=len(raw) - 1)
    with pytest.raises(_codec.CodecError, match="declared length"):
        _codec.unwrap(body(len(raw) - 1, frame), limit=len(raw))  # stops at size + 1
    with pytest.raises(_codec.CodecError, match="trailing or missing"):
        _codec.unwrap(body(len(raw), frame + b"junk"), limit=len(raw))
    with pytest.raises(_codec.CodecError):
        _codec.unwrap(body(len(raw), frame[:-8] + b"\0" * 8), limit=len(raw))


def test_xz_is_never_chosen_unless_asked(monkeypatch):
    assert _codec.default_codec() != "xz"
    monkeypatch.delenv("OPENTINE_COMPRESS", raising=False)
    assert _codec.wanted() != "xz"
    assert _codec.archival_codec() in ("xz", "zlib")
    with pytest.raises(SystemExit):
        main(["gc", "--codec", "xz"])  # repository packs stay readable by 0.34-0.36


# -- --archival -------------------------------------------------------------------

_BLOCK_ZSTD = """
import sys

class _Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in ("zstandard", "backports") or name == "compression.zstd":
            raise ImportError(f"{name} is blocked")
        return None

sys.meta_path.insert(0, _Block())
from opentine import _codec
from opentine.repository import Repo
from opentine.repository._archive import restore_archive

assert not _codec.available("zstd")
restore_archive(sys.argv[1], sys.argv[2])
repo = Repo.open(sys.argv[2])
result = repo.fsck()
assert result.ok and result.complete, result
print(json.dumps({"objects": result.objects, "main": repo.read_ref("heads/main")}))
"""


def test_an_archival_archive_verifies_without_zstd(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    run_id = repo.put_run(_run(20), ref="heads/main").run_id
    archive = tmp_path / "r.tinearc"
    main(["archive", "create", str(archive), "--repo", str(repo.path), "--archival"])
    data = archive.read_bytes()
    assert bytes(_codec.MAGIC + bytes([_codec.ZSTD])) not in data
    script = tmp_path / "verify.py"
    script.write_text("import json\n" + textwrap.dedent(_BLOCK_ZSTD), encoding="utf-8")
    out = subprocess.run(
        [sys.executable, str(script), str(archive), str(tmp_path / "copy")],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stdout.strip().splitlines()[-1])
    assert report == {"objects": len(repo.iter_oids()), "main": run_id}


def test_archival_and_codec_are_exclusive(tmp_path):
    with pytest.raises(SystemExit):
        main(["archive", "create", str(tmp_path / "a"), "--archival", "--codec", "zlib"])


@_XZ
def test_an_xz_archive_is_smaller_than_zlib(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(30), ref="heads/main")
    xz = create_archive(repo, tmp_path / "x", codec="xz")["archive_bytes"]
    assert xz < create_archive(repo, tmp_path / "z", codec="zlib")["archive_bytes"]


# -- --level ----------------------------------------------------------------------


def _capture_levels(monkeypatch) -> list:
    levels: list = []
    real = gc_module.write_pack

    def spy(root, objects, codec, level, fmt):
        levels.append(level)
        return real(root, objects, codec, level, fmt)

    monkeypatch.setattr(gc_module, "write_pack", spy)
    return levels


def test_gc_level_reaches_the_pack_writer(tmp_path, compress_on, monkeypatch, capsys):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    levels = _capture_levels(monkeypatch)
    main(["gc", "--repo", str(repo.path), "--codec", "zlib", "--level", "3", "--json"])
    assert levels == [3]
    assert json.loads(capsys.readouterr().out)["reaped_temp"] == 0
    with pytest.raises(SystemExit):
        main(["gc", "--repo", str(repo.path), "--level", "23"])


def test_autopack_takes_its_level_from_config(tmp_path, compress_on, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    config = repo.path / "config.json"
    value = json.loads(config.read_text(encoding="utf-8"))
    value["auto_pack"] = {"objects": 1, "level": 5}
    config.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    repo.put_run(_run(), ref="heads/main")
    monkeypatch.delenv("OPENTINE_AUTO_PACK")
    assert _autopack.level_kwargs(repo) == {"level": 5}
    levels = _capture_levels(monkeypatch)
    assert _autopack.maybe_autopack(Repo.open(repo.path), min_age=0) is not None
    assert levels == [5]


# -- X18: temp-file reaping ---------------------------------------------------------


def test_gc_reaps_only_stale_staging_files(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    old = time.time() - 2 * 3600
    stale = [repo.path / "packs" / ".abc.k3j_9x0q", repo.path / "refs" / ".x.tine.ab12cd34.tmp"]
    fresh = repo.path / "logs" / ".live.zz99yy88"
    other = repo.path / "logs" / "notes.txt"
    for path in (*stale, fresh, other):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"partial")
    for path in (*stale, other):
        os.utime(path, (old, old))
    result = gc(repo)
    assert result.reaped_temp == 2
    assert not any(path.exists() for path in stale)
    assert fresh.exists() and other.exists()
    assert Repo.open(repo.path).fsck().ok
    assert not is_staging(".DS_Store") and not is_staging("abc.k3j_9x0q")


# -- X19: F_FULLFSYNC -----------------------------------------------------------------


def test_full_fsync_uses_f_fullfsync_on_macos(monkeypatch, tmp_path):
    calls: list = []
    fake = types.SimpleNamespace(F_FULLFSYNC=51, fcntl=lambda fd, op: calls.append(op))
    monkeypatch.setitem(sys.modules, "fcntl", fake)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append("fsync"))
    _canon.full_fsync(0)
    assert calls == [51]

    def refuse(fd, op):
        raise OSError("not supported")

    fake.fcntl = refuse
    _canon.full_fsync(0)
    assert calls == [51, "fsync"]  # a filesystem without it falls back to fsync


def test_full_fsync_is_plain_fsync_elsewhere(monkeypatch):
    calls: list = []
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    _canon.full_fsync(7)
    assert calls == [7]


# -- fsck budget ----------------------------------------------------------------------


def test_fsck_stops_cleanly_at_its_budget(tmp_path, compress_on, capsys):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    full = repo.fsck()
    assert full.ok and full.complete and full.checked == full.objects > 3
    part = repo.fsck(max_objects=3)
    assert part.ok and not part.complete and part.checked == 3
    assert repo.fsck(budget=0).checked == 0
    main(["fsck", "--repo", str(repo.path), "--max-objects", "2"])
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["checked"] == 2 and report["complete"] is False and report["ok"] is True
    assert f"after 2 of {full.objects} objects" in captured.err
