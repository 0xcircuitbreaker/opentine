"""0.13 Footprint II: storage version 3 (opt-in ``tine gc --upgrade``)."""

from __future__ import annotations

import json
import os
import shutil
import time

import pytest

from opentine import Recorder, TraceEvent, cli
from opentine.repository import Repo
from opentine.repository import _run_delta as forms
from opentine.repository._autopack import maybe_autopack
from opentine.repository._config import read_config
from opentine.repository._gc import gc
from opentine.repository._gc_prune import prune
from opentine.repository._pack_v3 import stored_forms
from opentine.repository._pack_write import pack_version
from opentine.repository._packs import pack_set
from tests.test_backwards_compat import GOLDEN

OLD = 30 * 86400


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _record(repo, ref, steps=6, model=True) -> None:
    rec = Recorder.start(repo, ref=ref, prompt=f"task {ref}", capture=False)
    history = [{"role": "user", "content": f"task {ref}"}]
    for index in range(steps):
        rec.append(
            TraceEvent(
                kind="model" if model and index % 2 else "tool",
                timestamp=index + 1.0,
                trace_id="t",
                span_id=f"s{index}",
                actor="" if model and index % 2 else "read_file",
                inputs={"messages": list(history)},
                outputs={"text": f"{ref} body {index} " * 40},
            )
        )
        history.append({"role": "tool", "content": f"{ref} {index}"})
    rec.finalize()


def _all_raw(repo) -> dict[str, bytes]:
    return {oid: repo.raw(oid) for oid in repo.iter_oids()}


def _packs(repo) -> list[str]:
    return sorted(n[:64] for n in os.listdir(repo.path / "packs") if n.endswith(".tpk"))


def _version(repo) -> int:
    return read_config(repo.path / "config.json")["version"]


def test_upgrade_round_trips_every_object_and_downgrade_returns_to_v2(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    for ref in ("heads/a", "heads/b"):
        _record(repo, ref)
    before = _all_raw(repo)
    gc(repo)
    assert _version(repo) == 2 and all(pack_version(repo.path, d) == 1 for d in _packs(repo))
    gc(repo, upgrade=True)
    assert _version(repo) == 3 and [pack_version(repo.path, d) for d in _packs(repo)] == [3]
    reopened = Repo.open(repo.path)
    assert _all_raw(reopened) == before
    assert reopened.fsck().ok
    assert reopened.load_run("heads/a").id
    gc(reopened, downgrade=True)
    again = Repo.open(repo.path)
    assert _version(again) == 2 and [pack_version(again.path, d) for d in _packs(again)] == [1]
    assert "note" not in read_config(again.path / "config.json")
    assert _all_raw(again) == before and again.fsck().ok


def test_v3_pack_uses_run_deltas_and_slim_events(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a", steps=8)
    raw = _all_raw(repo)
    chosen = {oid: enc for oid, _, enc, _ in stored_forms(sorted(raw.items()))}
    runs = [oid for oid in raw if oid.startswith("run:")]
    assert sum(chosen[oid] == forms.RUN_DELTA for oid in runs) >= len(runs) - 2
    assert any(enc == forms.EVENT_SLIM for oid, enc in chosen.items() if oid.startswith("event:"))
    gc(repo, upgrade=True)
    packs = pack_set(repo.path)
    packs.refresh()
    (digest,) = packs.v3
    assert {e[4] for e in packs.v3[digest].values()} == {0, 1, 2}
    assert _all_raw(Repo.open(repo.path)) == raw


def test_v3_is_never_automatic(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a")
    os.environ["OPENTINE_AUTO_PACK"] = "1"
    assert maybe_autopack(repo, min_age=0) is not None
    assert _version(repo) == 2 and all(pack_version(repo.path, d) == 1 for d in _packs(repo))
    gc(repo, upgrade=True)
    _record(repo, "heads/b")
    maybe_autopack(repo, min_age=0)
    assert _version(repo) == 3 and all(pack_version(repo.path, d) == 3 for d in _packs(repo))


def test_stale_process_follows_a_downgrade(tmp_path):
    """A writer that opened the repo before a downgrade must not leave a v3 pack in a v2 repo."""
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a")
    gc(repo, upgrade=True)
    stale = Repo.open(repo.path)
    gc(Repo.open(repo.path), downgrade=True)
    _record(stale, "heads/b")
    gc(stale)
    assert all(pack_version(repo.path, d) == 1 for d in _packs(repo))
    assert Repo.open(repo.path).fsck().ok


def test_fsck_flags_a_v3_pack_left_in_a_v2_repository(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a")
    gc(repo, upgrade=True)
    config = json.loads((repo.path / "config.json").read_text())
    config["version"] = 2  # as a crash between the rewrite and the descriptor would
    (repo.path / "config.json").write_text(json.dumps(config))
    report = Repo.open(repo.path).fsck()
    assert not report.ok and "storage-v3 pack" in json.dumps([str(e) for e in report.errors])


def test_older_readers_refuse_a_v3_descriptor(tmp_path, monkeypatch):
    """0.11-0.12 accept descriptor versions (1, 2) only; this is the refusal they hit."""
    from opentine.repository import _config

    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a")
    gc(repo, upgrade=True)
    monkeypatch.setattr(_config, "_VERSIONS", (1, 2))
    with pytest.raises(ValueError, match="repository config is incompatible"):
        Repo.open(repo.path)
    monkeypatch.undo()
    config = json.loads((repo.path / "config.json").read_text())
    config["version"] = 4
    (repo.path / "config.json").write_text(json.dumps(config))
    with pytest.raises(ValueError, match="storage version 4 is newer"):
        Repo.open(repo.path)


@pytest.mark.parametrize("golden", GOLDEN, ids=[item.version for item in GOLDEN])
def test_every_golden_repo_round_trips_through_v3_with_identical_ids(golden, tmp_path):
    dest = tmp_path / "repo"
    shutil.copytree(golden.path / "repo", dest)
    repo = Repo.open(dest)
    before = _all_raw(repo)
    gc(repo, upgrade=True)
    upgraded = Repo.open(dest)
    assert _all_raw(upgraded) == before
    assert upgraded.fsck().ok
    assert upgraded.load_run(golden.repo_main_oid).id == f"compat-repo-source-{golden.version}"
    assert upgraded.load_run("heads/experiment").id == golden.repo_fork_oid
    gc(upgraded, downgrade=True)
    assert _all_raw(Repo.open(dest)) == before


def test_prune_rewrites_v3_packs_without_breaking_delta_chains(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/keep", steps=8)
    _record(repo, "heads/drop", steps=8)
    gc(repo, upgrade=True)
    for path in repo.path.rglob("drop"):  # the ref and its reflog
        path.unlink()
    stamp = time.time() - OLD
    for name in os.listdir(repo.path / "packs"):
        os.utime(repo.path / "packs" / name, (stamp, stamp))
    kept = _all_raw(repo)
    result = prune(repo, delete=True, git_links=False)
    assert result.deleted > 0
    after = Repo.open(repo.path)
    assert all(pack_version(after.path, d) == 3 for d in _packs(after))
    assert after.fsck().ok
    for oid in after.iter_oids():
        assert after.raw(oid) == kept[oid]
    assert after.load_run("heads/keep").id


def test_cli_gc_upgrade_and_downgrade(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a")
    cli.main(["gc", "--repo", str(repo.path), "--upgrade", "--json"])
    assert _version(repo) == 3
    cli.main(["gc", "--repo", str(repo.path), "--downgrade"])
    assert _version(repo) == 2
    assert "storage version 2" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["gc", "--repo", str(repo.path), "--upgrade", "--downgrade"])


def test_slim_and_delta_refuse_forms_that_would_not_round_trip():
    header = b'{"encoding":"json","schema":1,"type":"event"}'
    missing = header + b'\n{"actor":"","kind":"tool"}'  # lacks defaults a reader would add
    assert forms.slim_event(missing) is None
    noncanon = header + b'\n{"usage":{}, "actor":""}'
    assert forms.slim_event(noncanon) is None
    run = b'{"encoding":"json","schema":1,"type":"run"}'
    base = run + b'\n{"events":["a"],"x":1}'
    assert forms.run_delta(run + b'\n{"events":["a"], "x":2}', base) is None
    float_twin = run + b'\n{"events":["a"],"x":1.5}'
    stored = forms.run_delta(float_twin, base)
    assert stored is None or forms.apply_delta(base, forms.parse_delta(stored)) == float_twin
