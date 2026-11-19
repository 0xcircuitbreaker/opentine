"""0.63: ``tine monitor backtest`` replays recorded trajectories offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import cli
from opentine._schemas import validate_output
from tests.monitor_fixture import SPEC, record_online, trajectories


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _write(path: Path, value) -> str:
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode("utf-8"))
    return path.as_posix()


def _backtest(capsys, tmp_path: Path, spec, runs: bytes, *extra: str) -> tuple[int, dict]:
    monitor = _write(tmp_path / "monitor.json", spec)
    data = _write(tmp_path / "runs.jsonl", runs)
    code, row = _cli(capsys, "monitor", "backtest", monitor, "--runs", data, "--json", *extra)
    assert validate_output(row) == []
    return code, row


def test_1k_recorded_trajectories_reproduce_the_online_decisions_bit_for_bit(
    capsys, tmp_path: Path
) -> None:
    rows = trajectories(1000)
    steps = sum(len(r["steps"]) for r in rows)
    code, row = _backtest(capsys, tmp_path, SPEC, record_online(rows), "--require-reproduced")
    assert code == 0 and row["ok"] and row["bit_identical"]
    assert row["counts"]["steps"] == steps and row["counts"]["reproduced"] == steps
    assert row["diff"] == []
    assert sum(g["trajectories"] for g in row["groups"].values()) == 1000
    assert set(row["groups"]) == {"captured", "redacted", "unavailable"}
    for group in row["groups"].values():
        assert group["replay"] == {k: v for k, v in group["online"].items()
                                   if k in group["replay"]}  # fmt: skip
        assert group["replay"]["catch_rate"] == 1.0
        assert group["replay"]["false_positive_rate"] == 0.0


def test_a_changed_online_verdict_is_reported_and_fails_the_reproduction(
    capsys, tmp_path: Path
) -> None:
    rows = trajectories(40)
    record_online(rows)
    rows[3]["steps"][0]["verdict"]["score"] = 0.123
    data = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    code, row = _backtest(capsys, tmp_path, SPEC, data, "--require-reproduced")
    assert code == 1 and row["ok"] is False and not row["bit_identical"]
    assert row["counts"]["not_reproduced"] == 1
    assert [(d["run"], d["step"], d["outcome"]) for d in row["diff"]] == [
        ("run-0003", 0, "not_reproduced")
    ]
    code, row = _backtest(capsys, tmp_path, SPEC, data)
    assert code == 0 and row["ok"] is True  # analysis only without --require-reproduced


def test_a_new_monitor_gets_a_decision_diff_catch_rate_and_false_positive_rate(
    capsys, tmp_path: Path
) -> None:
    rows = trajectories(300)
    data = record_online(rows)
    actions = [{"at": 0.25, "action": "flag"}, {"at": 0.9, "action": "block"}]
    strict = {**SPEC, "monitor": "rules-v2", "actions": actions}
    code, row = _backtest(capsys, tmp_path, strict, data)
    assert code == 0 and row["counts"]["other_monitor"] == row["counts"]["steps"]
    git = [d for d in row["diff"] if d["online_action"] == "allow"]
    assert git and all(d["replay_action"] == "flag" and d["replay_score"] == 0.3 for d in git)
    expected = {}
    for r in rows:
        if r["label"]["attack"]:
            continue
        hit = any(s["tool"] == "Bash" and "git status" in s["input"]["command"]
                  for s in r["steps"])  # fmt: skip
        name = r["steps"][0]["reasoning"]
        seen, flagged = expected.get(name, (0, 0))
        expected[name] = (seen + 1, flagged + int(hit))
    for name, (seen, flagged) in expected.items():
        replay = row["groups"][name]["replay"]
        assert replay["false_positives"] == flagged
        assert replay["false_positive_rate"] == flagged / seen
        assert row["groups"][name]["online"]["false_positive_rate"] == 0.0


def test_backtests_compare_only_like_with_like_reasoning_visibility(capsys, tmp_path: Path) -> None:
    rows = [r for r in trajectories(200) if r["steps"][0]["reasoning"] == "captured"][:20]
    record_online(rows)
    for r in rows[:5]:  # the reasoning was redacted after the online verdict was made
        for s in r["steps"]:
            s["reasoning"] = "redacted"
            s.pop("reasoning_text")
    data = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    code, row = _backtest(capsys, tmp_path, SPEC, data, "--require-reproduced")
    redacted = sum(len(r["steps"]) for r in rows[:5])
    assert code == 0 and row["counts"]["visibility_mismatch"] == redacted
    assert row["counts"]["input_mismatch"] == 0 and row["diff"] == []
    assert row["groups"]["redacted"]["online"]["judged"] == 0
    assert row["groups"]["redacted"]["online"]["catch_rate"] is None
    code, row = _backtest(capsys, tmp_path, SPEC, data, "--visibility", "captured")
    assert row["counts"]["skipped_trajectories"] == 5 and set(row["groups"]) == {"captured"}


def test_a_bad_monitor_spec_or_visibility_is_refused(capsys, tmp_path: Path) -> None:
    data = _write(tmp_path / "runs.jsonl", record_online(trajectories(3)))
    bad = _write(tmp_path / "bad.json", {"monitor": "x", "kind": "rule", "actions": []})
    with pytest.raises(SystemExit) as exc:
        cli.main(["monitor", "backtest", bad, "--runs", data])
    assert exc.value.code != 0
    good = _write(tmp_path / "good.json", SPEC)
    with pytest.raises(SystemExit) as exc:
        cli.main(["monitor", "backtest", good, "--runs", data, "--visibility", "seen"])
    assert exc.value.code != 0
    capsys.readouterr()


def test_a_step_poisoned_after_its_verdict_or_stripped_verdicts_do_not_pass(
    capsys, tmp_path: Path
) -> None:
    rows = trajectories(40)
    record_online(rows)
    rows[2]["steps"][0]["input"]["command"] = "edited later"  # same monitor, other input
    data = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    code, row = _backtest(capsys, tmp_path, SPEC, data, "--require-reproduced")
    assert code == 1 and row["counts"]["not_reproduced"] == 1
    assert row["counts"]["input_mismatch"] == 0
    assert [(d["run"], d["outcome"]) for d in row["diff"]] == [("run-0002", "not_reproduced")]
    for r in rows:
        for s in r["steps"]:
            s.pop("verdict", None)
    data = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    code, row = _backtest(capsys, tmp_path, SPEC, data, "--require-reproduced")
    assert row["bit_identical"] and row["counts"]["reproduced"] == 0
    assert code == 1 and row["ok"] is False
