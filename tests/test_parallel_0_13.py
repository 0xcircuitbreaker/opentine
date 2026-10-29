"""0.13 F3: the parallel executor, the shared budget ledger, ``tine fan-out`` and
``tine run --parallel``. Members are ``sys.executable`` scripts (no external
binaries); waits are bounded polls on observable state, never fixed sleeps."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path

import pytest

from opentine import Run, StepKind, cli
from opentine.budget import SharedLedger
from opentine.parallel import Executor, Member, expand, parse_vary, render
from opentine.parallel._matrix import member_env
from opentine.repository import Repo, _fork_state
from opentine.repository._lockfile import pid_alive

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def _env(**extra: str) -> dict[str, str]:
    return member_env(["PYTHONPATH"], extra)


def _gone(pid: int, seconds: float = 20.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:  # a zombie is dead: it only waits for its new parent to reap it
            if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                return True
        except (FileNotFoundError, ProcessLookupError, IndexError):
            if sys.platform.startswith("linux"):
                return True
        except OSError:
            pass
        if not sys.platform.startswith("linux") and not pid_alive(pid):
            return True
        time.sleep(0.05)
    return False


# -- matrix ---------------------------------------------------------------------------


def test_vary_expands_in_a_stable_order_with_repeats():
    vary = parse_vary(["model=a,b", "seed=1,2"])
    rows = expand(vary, 2)
    assert len(rows) == 8 and rows[0] == rows[1] == {"model": "a", "seed": "1"}
    assert rows[-1] == {"model": "b", "seed": "2"}


@pytest.mark.parametrize("spec", ["Model=a", "model", "model=a,,b", "x=a\x00", "a b=c"])
def test_bad_vary_specs_are_refused(spec):
    with pytest.raises(ValueError):
        parse_vary([spec])


def test_member_cap_and_repeat_bounds():
    with pytest.raises(ValueError):
        expand({"a": [str(i) for i in range(100)]}, 11)
    with pytest.raises(ValueError):
        expand({}, 0)


def test_render_is_one_non_recursive_pass_and_never_splits_tokens():
    values = {"model": "{seed}", "seed": "1", "prompt": "a b; rm -rf /"}
    argv = render(["run", "--model={model}", "{prompt}", "{unknown}", "{0.__class__}"], values)
    assert argv == ["run", "--model={seed}", "a b; rm -rf /", "{unknown}", "{0.__class__}"]


def test_a_value_that_would_become_an_option_is_refused():
    with pytest.raises(ValueError, match="option"):
        render(["tool", "{model}"], {"model": "--harness-command=evil"})
    assert render(["--x={model}"], {"model": "-1"}) == ["--x=-1"]  # inside a token: data


def test_member_env_is_an_allowlist(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("OPENTINE_SIGNING_KEY", "k")
    monkeypatch.setenv("SOMETHING_ELSE", "v")
    env = member_env([], {"OPENTINE_FANOUT_ID": "x"})
    assert "ANTHROPIC_API_KEY" not in env and "OPENTINE_SIGNING_KEY" not in env
    assert "SOMETHING_ELSE" not in env and env["OPENTINE_FANOUT_ID"] == "x"
    assert member_env(["ANTHROPIC_API_KEY"], {})["ANTHROPIC_API_KEY"] == "sk-ant-secret"
    with pytest.raises(ValueError):
        member_env(["A=B"], {})


# -- ledger ---------------------------------------------------------------------------


def test_ledger_reports_are_cumulative_and_race_free():
    ledger = SharedLedger(1000)
    barrier = threading.Barrier(16)

    def worker(index: int) -> None:
        barrier.wait()
        for step in range(1, 101):
            ledger.report(str(index), Decimal(step) / 100)  # cumulative: ends at 1.00

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert ledger.total() == Decimal(16) and ledger.admit()
    ledger.report("0", "0.5")  # a stale, lower report never lowers what was spent
    assert ledger.total() == Decimal(16)


def test_ledger_closes_at_the_limit_and_fails_closed_on_unknown_cost():
    ledger = SharedLedger(1.0)
    assert ledger.report("a", "0.6") and not ledger.report("b", "0.4")
    assert ledger.closed and ledger.reason == "cost" and not ledger.admit()
    for bad in ("NaN", "-1", "inf", "zz"):
        assert SharedLedger(1.0).report("a", bad) is False
    unknown = SharedLedger(1.0)
    unknown.unknown("a")
    assert unknown.reason == "cost_completeness"
    unlimited = SharedLedger()
    unlimited.unknown("a")
    assert unlimited.report("a", "NaN") and unlimited.admit()


# -- executor -------------------------------------------------------------------------

SLOT = """
import os, sys
root, jobs = sys.argv[1], int(sys.argv[2])
for slot in range(jobs + 1):
    try:
        os.mkdir(os.path.join(root, f"slot{slot}"))
        break
    except FileExistsError:
        continue
open(os.path.join(root, f"took-{slot}-{os.getpid()}"), "w").close()
for _ in range(200000):
    pass
os.rmdir(os.path.join(root, f"slot{slot}"))
"""


def test_the_jobs_limit_is_never_exceeded(tmp_path):
    members = [Member(str(i), [PY, "-c", SLOT, str(tmp_path), "3"], _env()) for i in range(10)]
    executor = Executor(members, jobs=3)
    outcomes = executor.run()
    assert {o.status for o in outcomes.values()} == {"ok"} and len(outcomes) == 10
    taken = {name.split("-")[1] for name in os.listdir(tmp_path) if name.startswith("took")}
    assert "3" not in taken and executor.peak <= 3


GRANDCHILD = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
open(sys.argv[1], "w").write(str(child.pid))
time.sleep(120)
"""


def test_timeout_kills_the_member_and_its_process_tree(tmp_path):
    pidfile = tmp_path / "pid"
    member = Member("0", [PY, "-c", GRANDCHILD, str(pidfile)], _env())
    events = []
    outcome = Executor([member], jobs=1, timeout=1.5, on_event=events.append).run()["0"]
    assert outcome.status == "timeout"
    deadline = time.monotonic() + 20
    while not pidfile.exists() or not pidfile.read_text():
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert _gone(int(pidfile.read_text()))
    assert [e["event"] for e in events] == ["start", "exit"]


BUDGET = """
import os, sys, time
open(os.environ["OPENTINE_FANOUT_COST_FILE"], "w").write(sys.argv[1])
time.sleep(120)
"""


def test_budget_exhaustion_stops_running_members_and_starts_no_more(tmp_path):
    members = [
        Member(
            str(i),
            [PY, "-c", BUDGET, "0.75"],
            _env(OPENTINE_FANOUT_COST_FILE=str(tmp_path / f"{i}.cost")),
            cost_file=tmp_path / f"{i}.cost",
        )
        for i in range(5)
    ]
    ledger = SharedLedger(1.0)
    outcomes = Executor(members, jobs=2, ledger=ledger, timeout=60).run()
    statuses = sorted(o.status for o in outcomes.values())
    assert statuses == ["budget", "budget", "skipped", "skipped", "skipped"]
    assert ledger.reason == "cost" and ledger.total() == Decimal("1.5")


def test_unknown_cost_with_a_budget_fails_closed(tmp_path):
    members = [
        Member(str(i), [PY, "-c", "pass"], _env(), cost_file=tmp_path / f"{i}.cost")
        for i in range(3)
    ]
    outcomes = Executor(members, jobs=1, ledger=SharedLedger(5.0)).run()
    assert [outcomes[k].status for k in "012"] == ["ok", "skipped", "skipped"]


def test_stop_kills_running_members(tmp_path):
    started = threading.Event()
    member = Member("0", [PY, "-c", "import time; time.sleep(120)"], _env())
    executor = Executor(
        [member], jobs=1, on_event=lambda e: e["event"] == "start" and started.set()
    )
    thread = threading.Thread(target=executor.run)
    thread.start()
    assert started.wait(30)
    executor.stop()
    thread.join(30)
    assert executor.outcomes["0"].status == "stopped"


def test_members_get_argv_lists_only(tmp_path):
    marker = tmp_path / "pwned"
    member = Member("0", [PY, "-c", "import sys; print(sys.argv)", f"; touch {marker}"], _env())
    assert Executor([member], jobs=1).run()["0"].status == "ok"
    assert not marker.exists()


# -- tine fan-out ---------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    store = Repo.init(tmp_path)
    run = Run(id="base0001", model_info="m-old")
    for index in range(4):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    store.put_run(run, ref="heads/main")
    return store


def _main(argv: list[str]) -> int:
    try:
        cli.main(argv)
    except SystemExit as exc:
        return exc.code or 0
    return 0


def _lines(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]


def test_fan_out_prepares_forks_with_one_walk_and_one_transaction(repo, capsys, monkeypatch):
    calls = []
    original = _fork_state._closure
    monkeypatch.setattr(_fork_state, "_closure", lambda *a: calls.append(a) or original(*a))
    assert (
        _main(["fan-out", "heads/main", "--from-step", "2", "--vary", "model=x,y,z", "--json"]) == 0
    )
    event = _lines(capsys)[0]
    assert event["event"] == "prepared" and event["members"] == 3
    assert len(calls) == 1  # one walk of the run for N forks
    refs = {k: v for k, v in repo.list_refs().items() if k.startswith("experiments/fanout/")}
    assert len(refs) == 3
    models = sorted(repo.get(v).payload()["model"] for v in refs.values())
    assert models == ["x", "y", "z"]
    for oid in refs.values():
        assert len(repo.get(oid).payload()["events"]) == 2
    from opentine.repository._annotations import load_run_annotation

    metadata, _ = load_run_annotation(repo, repo.read_ref("heads/main"))
    (record,) = [v for k, v in metadata.items() if k.startswith("opentine.fanout.")]
    assert record["format"] == "opentine-fanout/1" and len(record["members"]) == 3


ECHO = """
import os, sys
out = os.path.join(sys.argv[1], os.environ["OPENTINE_FANOUT_INDEX"])
with open(out, "a") as handle:
    handle.write(" ".join([os.environ["OPENTINE_FANOUT_RUN"], sys.argv[2], "\\n"]))
open(os.environ["OPENTINE_FANOUT_COST_FILE"], "w").write("0.25")
sys.exit(int(sys.argv[3]))
"""


def test_fan_out_runs_members_and_streams_ndjson(repo, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-leak")
    out = tmp_path / "out"
    out.mkdir()
    cmd = [PY, "-c", ECHO + "\nassert 'ANTHROPIC_API_KEY' not in os.environ", str(out)]
    argv = ["fan-out", "heads/main", "--vary", "model=a,b", "--jobs", "2", "--env", "PYTHONPATH"]
    assert _main([*argv, "--json", "--", *cmd, "{model}", "0"]) == 0
    lines = _lines(capsys)
    assert lines[-1]["event"] == "summary" and lines[-1]["counts"] == {"ok": 2}
    assert lines[-1]["spent"] == "0.50"
    assert all("argv" not in line and "env" not in line for line in lines)
    for index, model in (("0", "a"), ("1", "b")):
        run, seen = (out / index).read_text().split()[:2]
        assert (
            seen == model
            and repo.read_ref(f"experiments/fanout/{lines[0]['fanout']}/{index}") == run
        )


def test_resume_reruns_only_unfinished_members(repo, capsys, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    cmd = ["--", PY, "-c", ECHO, str(out), "x", "0"]
    assert (
        _main(["fan-out", "heads/main", "--repeat", "3", "--json", "--env", "PYTHONPATH", *cmd])
        == 0
    )
    fid = _lines(capsys)[-1]["fanout"]
    state_path = repo.path / "fanouts" / f"{fid}.json"
    state = json.loads(state_path.read_text())
    state["members"][1]["status"] = "timeout"
    state_path.write_text(json.dumps(state))
    assert _main(["fan-out", "--resume", fid, "--env", "PYTHONPATH", "--json", *cmd]) == 0
    counts = {i: len((out / str(i)).read_text().splitlines()) for i in range(3)}
    assert counts == {0: 1, 1: 2, 2: 1}
    other = ["--", PY, "-c", "print('different')"]
    assert _main(["fan-out", "--resume", fid, *other]) != 0  # not the recorded command
    assert len((out / "1").read_text().splitlines()) == 2


@pytest.mark.parametrize(
    "tamper",
    [
        lambda s: s.update(command_digest="0" * 63),
        lambda s: s["members"][0].update(status="bogus"),
        lambda s: s["members"][0]["vary"].update({"BAD": "x"}),
        lambda s: s["members"][0].update(key="7"),
        lambda s: s.update(extra=1),
    ],
)
def test_a_tampered_state_file_is_refused(repo, capsys, tamper):
    cmd = ["--", PY, "-c", "pass"]
    _main(["fan-out", "heads/main", "--json", *cmd])
    fid = _lines(capsys)[-1]["fanout"]
    path = repo.path / "fanouts" / f"{fid}.json"
    state = json.loads(path.read_text())
    tamper(state)
    path.write_text(json.dumps(state))
    assert _main(["fan-out", "--resume", fid, *cmd]) != 0
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("fid", ["../../x", "ABCDEF012345", "short"])
def test_resume_ids_cannot_name_paths(repo, fid):
    assert _main(["fan-out", "--resume", fid, "--", PY, "-c", "pass"]) != 0


def test_fan_out_members_can_get_their_own_worktrees(repo, capsys, tmp_path):
    trees = tmp_path / "trees"
    probe = "import os; open('here', 'w').write(os.getcwd())"
    assert _main(["fan-out", "heads/main", "--repeat", "2", "--worktree-dir", str(trees),
                  "--json", "--", PY, "-c", probe]) == 0  # fmt: skip
    dirs = sorted(p for p in trees.iterdir())
    assert len(dirs) == 2 and all(
        (d / "here").exists() and (d / ".tine-worktree").exists() for d in dirs
    )
    from opentine import _worktree

    assert len(_worktree.list_worktrees(repo)) == 2


# -- tine run --parallel --------------------------------------------------------------


def test_run_parallel_reinvokes_tine_run_per_member(repo, capsys, tmp_path):
    script = tmp_path / "agent.py"
    script.write_text(
        "from opentine import Run, StepKind\n"
        "run = Run(id='p', model_info='m')\n"
        "run.add_step(StepKind.model, {'text': 'q'}, {'text': 'a'})\n"
    )
    code = _main(["run", str(script), "--parallel", "2", "--env", "PYTHONPATH", "--json"])
    lines = _lines(capsys)
    assert code == 0, lines
    assert lines[-1]["counts"] == {"ok": 2}


def test_parallel_only_flags_need_parallel(repo, capsys, tmp_path):
    assert _main(["run", "x.py", "--jobs", "2"]) != 0


def test_member_argv_strips_fan_out_flags_including_abbreviations():
    from opentine._cli_fanout import _member_argv

    argv = ["run", "s.py", "--parallel", "3", "--jobs=2", "--vary", "model=a", "--json",
            "--save", "o.tine", "--budg", "1"]  # fmt: skip
    assert _member_argv(argv)[4:] == ["run", "s.py", "--save", "o.tine"]


def test_run_parallel_refuses_a_shared_save_path(repo):
    assert _main(["run", "x.py", "--parallel", "2", "--save", "one.tine"]) != 0


def test_run_parallel_flags_match_the_refusal_table():
    from opentine._cli_fanout import PARALLEL_DEFAULTS
    from opentine._cli_parser import _build_parser

    subs = next(a for a in _build_parser()._actions if hasattr(a, "choices") and a.choices)
    actions = {a.dest: a for a in subs.choices["run"]._actions}
    for dest, default in PARALLEL_DEFAULTS.items():
        assert actions[dest].default == default, dest
    assert actions["parallel"].default is None


def test_option_shaped_values_are_refused_before_any_fork(repo):
    argv = ["fan-out", "heads/main", "--vary", "model=-x", "--", PY, "-c", "pass", "{model}"]
    assert _main(argv) != 0
    assert not any(k.startswith("experiments/fanout/") for k in repo.list_refs())


def test_a_prepared_fan_out_can_be_run_later(repo, capsys, tmp_path):
    assert _main(["fan-out", "heads/main", "--repeat", "2", "--json"]) == 0
    fid = _lines(capsys)[0]["fanout"]
    out = tmp_path / "out"
    out.mkdir()
    cmd = ["--", PY, "-c", ECHO, str(out), "x", "0"]
    assert _main(["fan-out", "--resume", fid, "--env", "PYTHONPATH", "--json", *cmd]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["0", "1"]
