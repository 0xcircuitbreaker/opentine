"""A deterministic three-generation lineage for the 0.72 ``tine trends`` tests.

``build(base)`` initialises a repository, pins key roles (EVALER scores,
DATASET signs task lengths, RECORDER is the loop's optimizer key), and records

* ``root`` (RUN_A): 80 items over 8 task lengths, success falling with length;
* ``child`` (RUN_B, parent root): better at every length;
* ``worse`` (RUN_C, parent child): much worse, a regression against ``child``.

Each eval has its own ``created_at``, so the three evals have distinct ids.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentine._eval_run import run_eval
from opentine._eval_scorers import parse
from opentine._lineage import record
from opentine._trends_lengths import sign
from opentine.repository import Repo
from tests.lineage_helpers import RECORDER, art
from tests.promote_helpers import AT, EVALER, RUN_A, RUN_B, RUN_C, fingerprint, key

DATASET = "9e" * 32
LENGTHS = ("2", "4", "8", "15", "30", "60", "120", "240")
N = 80
SHAPES = {  # percent passing per length, shortest first
    RUN_A: (95, 90, 80, 65, 45, 30, 15, 5),
    RUN_B: (98, 95, 92, 85, 70, 55, 35, 15),
    RUN_C: (60, 45, 30, 20, 10, 5, 5, 0),
}


def minutes(i: int) -> str:
    return LENGTHS[i % len(LENGTHS)]


def passing(run: str, i: int) -> bool:
    return (i * 37) % 100 < SHAPES[run][i % len(LENGTHS)]


def items() -> list[dict[str, str]]:
    return [{"id": f"main-{i:03d}", "input": f"task {i}", "expected": "yes"} for i in range(N)]


def dataset() -> str:
    """The eval dataset digest the task lengths are bound to."""
    from opentine._eval_dataset import dataset_digest

    return dataset_digest(items())


def make_eval(out: Path, run: str, when: str) -> Path:
    outputs = {f"main-{i:03d}": {"output": "yes" if passing(run, i) else "no", "run": run}
               for i in range(N)}  # fmt: skip
    run_eval(items(), parse("exact"), key(EVALER), out, outputs=outputs, created_at=when)
    return out


def roles_toml(dataset: str = DATASET) -> str:
    return (f'version = 1\n[roles]\nscorer = ["{fingerprint(EVALER)}"]\n'
            f'dataset = ["{fingerprint(dataset)}"]\nverdict = ["{fingerprint(EVALER)}"]\n'
            f'optimizer = ["{fingerprint(RECORDER)}"]\n')  # fmt: skip


def write_lengths(root: Path, signer: str = DATASET, bound: str | None = None) -> Path:
    lengths = {f"main-{i:03d}": minutes(i) for i in range(N)}
    bound = bound or dataset()
    signed = sign(lengths, key(signer), suite="synthetic", dataset=bound, at=AT)
    path = root / ".tine" / "trends" / "task-lengths.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(signed, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return path


def build(base: Path, *, pin: bool = True) -> tuple[Path, dict[str, str]]:
    """The repository root and the named variants."""
    from tests.key_roles_helpers import pin_roles

    root = base / "repo"
    repo = Repo.init(root)
    (Path(repo.path) / "key-roles.toml").write_bytes(roles_toml().encode("utf-8"))
    if pin:
        pin_roles(Path(repo.path))
    store = root / ".tine" / "lineage"
    sign_key = key(RECORDER)
    v: dict[str, str] = {}
    parent: list[str] = []
    for name, run, n, when in (("root", RUN_A, 0, "2026-11-01T12:00:00Z"),
                               ("child", RUN_B, 1, "2026-11-01T12:00:01Z"),
                               ("worse", RUN_C, 2, "2026-11-01T12:00:02Z")):  # fmt: skip
        folder = make_eval(base / f"eval-{name}", run, when)
        v[name] = record(sign_key, run=run, artifacts=art(100 + n), store=store, parents=parent,
                         evals=[folder], at=AT)["variant"]  # fmt: skip
        parent = [v[name]]
    write_lengths(root)
    return root, v


__all__ = ["DATASET", "LENGTHS", "N", "build", "dataset", "items", "make_eval", "minutes",
           "passing", "roles_toml", "write_lengths"]  # fmt: skip
