"""0.58: the two cheap pack defaults, each flipped only where every supported reader reads it.

* At-rest auto-pack writes the current local pack format (``TINELP3``): this
  tree, the TypeScript verifier (conformance family ``29-localpack``) and the
  0.34 peer-compat reader all read it; ``tine-verify.pyz`` reads no repository.
* ``Repo.pack()`` stays ``TINEPACK3``: the 0.34 peer-compat reader cannot read
  ``TINEPACK5`` (0.37+), shown here against ``git archive v0.34.0``.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository._autopack import maybe_autopack
from opentine.repository._gc import gc
from opentine.repository._pack5 import from_v3

ROOT = Path(__file__).resolve().parents[1]


def _repo(path: Path, labels: str = "ab") -> Repo:
    repo = Repo.init(path, compression="zstd")
    for label in labels:
        run = Run(id=label, model_info="m", user_prompt="p", policies=PolicySet().to_dict())
        run.add_step(StepKind.done, {"text": f"{label} done"})
        repo.put_run(run, ref="heads/main")
    return repo


def _config(repo: Repo) -> dict:
    return json.loads((repo.path / "config.json").read_bytes())


def _magics(repo: Repo) -> set[bytes]:
    packs = (repo.path / "packs").glob("*.tpk")
    return {p.read_bytes()[:8] for p in packs}


@pytest.fixture
def autopack_now(monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "1")
    monkeypatch.setenv("OPENTINE_RUN_PACK", "0")  # objects stay loose until auto-pack
    monkeypatch.delenv("OPENTINE_AUTO_PACK_FORMAT", raising=False)


def test_autopack_moves_a_v2_repository_to_v3_and_writes_tinelp3(tmp_path, autopack_now):
    repo = _repo(tmp_path / "r")
    assert _config(repo)["version"] == 2
    oids = sorted(repo.iter_oids())
    assert maybe_autopack(repo, min_age=0) is not None
    assert _config(repo)["version"] == 3
    assert _magics(repo) == {b"TINELP3\n"}
    fresh = Repo.open(repo.path)
    assert sorted(fresh.iter_oids()) == oids and all(fresh.raw(o) for o in oids)
    assert fresh.fsck().ok


def test_after_the_move_a_runs_own_pack_is_tinelp3_too(tmp_path, autopack_now, monkeypatch):
    repo = _repo(tmp_path / "r", "a")
    assert maybe_autopack(repo, min_age=0) is not None
    before = set((repo.path / "packs").glob("*.tpk"))
    monkeypatch.delenv("OPENTINE_RUN_PACK")
    run = Run(id="b", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "b"})
    repo.put_run(run, ref="heads/main")
    new = set((repo.path / "packs").glob("*.tpk")) - before
    assert new and {p.read_bytes()[:8] for p in new} == {b"TINELP3\n"}


def test_older_v1_packs_keep_reading_after_the_move(tmp_path, autopack_now, monkeypatch):
    repo = _repo(tmp_path / "r", "a")
    monkeypatch.setenv("OPENTINE_AUTO_PACK_FORMAT", "1")
    assert maybe_autopack(repo, min_age=0) is not None
    assert _magics(repo) == {b"TINELP1\n"} and _config(repo)["version"] == 2
    first = sorted(repo.iter_oids())
    monkeypatch.delenv("OPENTINE_AUTO_PACK_FORMAT")
    run = Run(id="b", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "b"})
    repo.put_run(run, ref="heads/main")
    assert maybe_autopack(repo, min_age=0) is not None
    assert _config(repo)["version"] == 3
    assert b"TINELP3\n" in _magics(repo)
    fresh = Repo.open(repo.path)
    assert fresh.fsck().ok and all(fresh.raw(o) for o in first)


def test_an_explicit_downgrade_is_never_undone_by_autopack(tmp_path, autopack_now):
    repo = _repo(tmp_path / "r")
    gc(repo, upgrade=True)
    gc(repo, downgrade=True)
    assert _config(repo)["version"] == 2
    assert _config(repo)["auto_pack"] == {"format": 1}
    run = Run(id="c", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "c"})
    repo.put_run(run, ref="heads/main")
    maybe_autopack(repo, min_age=0)
    assert _config(repo)["version"] == 2 and _magics(repo) == {b"TINELP1\n"}


def test_a_disabled_autopack_stays_disabled_after_a_downgrade(tmp_path):
    repo = _repo(tmp_path / "r")
    path = repo.path / "config.json"
    path.write_bytes(json.dumps({**_config(repo), "auto_pack": False}).encode())
    gc(repo, upgrade=True)
    gc(repo, downgrade=True)
    assert _config(repo)["auto_pack"] is False


def test_repo_pack_default_is_tinepack3(tmp_path):
    # Left as is: the 0.34 peer-compat reader refuses TINEPACK5 (test below).
    assert _repo(tmp_path / "r").pack()[:10] == b"TINEPACK3\0"


def _v034(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    try:
        archive = subprocess.run(
            ["git", "-C", str(ROOT), "archive", "v0.34.0", "opentine"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("tag v0.34.0 is not available in this checkout")
    dest = tmp_path / "v034"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return dest


OLD_READER = """
import json, sys
sys.path.insert(0, sys.argv[1])
from opentine.repository import Repo
out = {}
for name in ("p3", "p5"):
    try:
        data = open(sys.argv[2] + "/" + name, "rb").read()
        Repo.init(sys.argv[2] + "/imp-" + name).import_pack(data)
        out[name] = "ok"
    except Exception as exc:
        out[name] = type(exc).__name__ + ": " + str(exc)
repo = Repo.open(sys.argv[2] + "/r")
oids = list(repo.iter_oids())
out["objects"] = sum(1 for o in oids if repo.get(o))
out["fsck"] = repo.fsck().ok
print(json.dumps(out))
"""


@pytest.mark.filterwarnings("ignore::Warning")
def test_the_034_reader_refuses_tinepack5_and_reads_an_autopacked_repository(
    tmp_path, autopack_now
):
    old = _v034(tmp_path)
    work = tmp_path / "w"
    repo = _repo(work / "r")
    pack = repo.pack()
    (work / "p3").write_bytes(pack)
    (work / "p5").write_bytes(from_v3(pack))
    assert maybe_autopack(repo, min_age=0) is not None and _config(repo)["version"] == 3
    count = len(list(repo.iter_oids()))
    code = OLD_READER
    done = subprocess.run(
        [sys.executable, "-I", "-c", code, str(old), str(work)],
        capture_output=True,
        text=True,
        check=True,
        cwd=tmp_path,
    )
    out = json.loads(done.stdout.strip().splitlines()[-1])
    assert out["p3"] == "ok"
    assert out["p5"] != "ok" and "pack header" in out["p5"]  # why Repo.pack() stays v3
    assert out["objects"] == count and out["fsck"] is True
