"""A small repository for the 0.65 ``tine query`` tests: runs, a monitor verdict, an eval."""

from __future__ import annotations

import json
from pathlib import Path

from opentine import _monitor_verdict, cli
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from tests.promote_helpers import key, make_eval

MONITOR_SEED, OTHER_SEED, SCORER_SEED = "11" * 32, "22" * 32, "5a" * 32
DIGEST = "sha256:" + "d" * 64


def add_run(repo: Repo, name: str, cost: float, model: str = "m1") -> str:
    run = Run(id=name, model_info=model)
    run.add_step(StepKind.model, {"q": name}, {"a": 1}, cost=cost,
                 usage={"input_tokens": 10, "output_tokens": 4})  # fmt: skip
    run.add_step(StepKind.tool, {"q": name + "-tool"}, {"a": 2}, tool_info={"name": "ls"})
    return repo.put_run(run, ref=f"heads/{name}").run_id


def claim(session: str, action: str = "flag") -> dict:
    return {"convention": _monitor_verdict.CONVENTION, "monitor": {"id": "rm-rf", "kind": "rule"},
            "input_digest": DIGEST, "reasoning": {"state": "unavailable", "digest": None},
            "tool": "shell", "session": session, "score": 0.9, "threshold": 0.5,
            "action": action, "enforced": False, "mode": "advisory", "decided_by": "monitor",
            "latency_ms": 1, "deadline_ms": 100, "fail_closed": False,
            "trajectories": [{"role": "original", "digest": DIGEST}], "chosen": "original",
            "stop": None, "decided_at": "2026-12-01T10:00:00Z"}  # fmt: skip


def build(base: Path, *, pin: bool = True) -> dict:
    """``{"repo", "runs", "pinned", "other", "evals"}``; the monitor key is pinned."""
    from opentine._signing_pins import key_fingerprint
    from tests.key_roles_helpers import pin_roles

    repo = Repo.init(base / "r")
    runs = [add_run(repo, f"run{i}", cost=0.25 * (i + 1)) for i in range(3)]
    monitor = key_fingerprint(key(MONITOR_SEED).public_key().public_bytes_raw())
    scorer = key_fingerprint(key(SCORER_SEED).public_key().public_bytes_raw())
    if pin:
        text = f"version = 1\n[roles]\nmonitor = {json.dumps([monitor])}\n"
        text += f"scorer = {json.dumps([scorer])}\n"
        text += f'dataset = ["sha256:{"e" * 64}"]\nverdict = ["sha256:{"f" * 64}"]\n'
        (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
        pin_roles(repo.path)
    pinned = _monitor_verdict.record(repo, runs[0], claim("s1"), key(MONITOR_SEED))
    other = _monitor_verdict.record(repo, runs[1], claim("s2", "block"), key(OTHER_SEED))
    evals = make_eval(base / "ev", runs[0], lambda i: i % 2 == 0, n=4)
    return {"repo": repo, "runs": runs, "pinned": pinned, "other": other, "evals": evals}


def tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    try:
        cli.main([*argv, "--json"])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip() else {}
