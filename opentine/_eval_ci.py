"""``tine eval ci``: push-triggered evals from ``.tine/evals.toml`` (0.47).

One config, three places to run it: locally, in CI (the gate action's
``evals-config`` input runs this command on every push) or on a self-hosted
runner. Each ``[[eval]]`` table names a dataset and a scorer and is run with
``tine eval run`` into ``<out>/<name>/``, signed with the one ``--key``::

    [defaults]
    threshold = 1.0          # an item passes at this score
    min_pass_rate = 1.0      # an eval passes when passed / items reaches this

    [[eval]]
    name = "smoke"
    dataset = "evals/smoke.jsonl"
    scorer = "exact"
    outputs = "evals/smoke-outputs.jsonl"     # optional
    run = "run:sha256:..."                    # optional default run
    judge_prompt = "judge@production"         # llm-judge only: a registered prompt

Paths are relative to the directory holding ``.tine/``. ``judge_prompt``
resolves through the prompt registry (SPEC 4.19) and must verify; its
``{{input}}``, ``{{expected}}`` and ``{{output}}`` placeholders become the
judge's template, so every signed verdict's ``scorer_version`` pins the
registered prompt's bytes, and the summary names its digest.
"""

from __future__ import annotations

import re
import tomllib
from decimal import Decimal
from pathlib import Path
from typing import Any

CONFIG = Path(".tine") / "evals.toml"
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_KEYS = {"name", "dataset", "scorer", "outputs", "run", "threshold", "min_pass_rate",
         "judge_prompt"}  # fmt: skip
_JUDGE_VARIABLES = {"input", "expected", "output"}
MAX_EVALS = 64


class ConfigError(ValueError):
    """``.tine/evals.toml`` is missing, unreadable or names something it may not."""


def _fraction(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
        raise ConfigError(f"{name} must be a number from 0 to 1")
    return float(value)


def load(path: Path) -> list[dict[str, Any]]:
    """The evals *path* declares, defaults applied; :class:`ConfigError` else."""
    try:
        config = tomllib.loads(path.read_text("utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"no eval config at {path.as_posix()}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path.as_posix()} is not TOML: {exc}") from exc
    defaults = config.get("defaults", {})
    tables = config.get("eval", [])
    if not isinstance(defaults, dict) or not isinstance(tables, list) or not tables:
        raise ConfigError("the config needs at least one [[eval]] table")
    if len(tables) > MAX_EVALS:
        raise ConfigError(f"at most {MAX_EVALS} evals")
    out, seen = [], set()
    for table in tables:
        if not isinstance(table, dict) or set(table) - _KEYS:
            raise ConfigError(f"unknown key in [[eval]]: {sorted(set(table) - _KEYS)}")
        name = table.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in seen:
            raise ConfigError(f"eval name {name!r} must be unique and [a-z0-9][a-z0-9._-]*")
        seen.add(name)
        for key in ("dataset", "scorer"):
            if not isinstance(table.get(key), str):
                raise ConfigError(f"eval {name} needs a {key}")
        merged = {"threshold": 1.0, "min_pass_rate": 1.0, "outputs": None, "run": None,
                  "judge_prompt": None, **{k: v for k, v in defaults.items() if k in _KEYS},
                  **table}  # fmt: skip
        merged["threshold"] = _fraction(merged["threshold"], "threshold")
        merged["min_pass_rate"] = _fraction(merged["min_pass_rate"], "min_pass_rate")
        out.append(merged)
    return out


def judge_template(record: dict[str, Any]) -> str:
    """A registered prompt as the judge's ``str.format`` template."""
    from opentine._prompt import PLACEHOLDER

    extra = set(record["variables"]) - _JUDGE_VARIABLES
    if extra:
        raise ConfigError(f"a judge prompt may only use input, expected, output: {sorted(extra)}")
    pieces, last = [], 0
    for match in PLACEHOLDER.finditer(record["template"]):
        pieces.append(
            record["template"][last : match.start()].replace("{", "{{").replace("}", "}}")
        )
        pieces.append("{" + match.group(1) + "}")
        last = match.end()
    pieces.append(record["template"][last:].replace("{", "{{").replace("}", "}}"))
    return "".join(pieces)


def _one(entry: dict[str, Any], base: Path, key: Any, out: Path, repo: Any, when: Any) -> dict:
    from opentine import _prompt
    from opentine._eval_dataset import read_jsonl
    from opentine._eval_run import run_eval
    from opentine._eval_scorers import parse

    prompt, link = None, None
    if entry["judge_prompt"]:
        if not entry["scorer"].startswith("llm-judge:"):
            raise ConfigError(f"eval {entry['name']}: judge_prompt needs an llm-judge scorer")
        from opentine.repository import _registry_refs as refs

        record = refs.resolve(repo, entry["judge_prompt"])
        found = _prompt.check(record)
        prompt = judge_template(record)
        link = {k: found[k] for k in ("name", "version", "digest")}
    scorer = parse(entry["scorer"], prompt=prompt) if prompt else parse(entry["scorer"])
    outputs = None
    if entry["outputs"]:
        rows = read_jsonl(base / entry["outputs"])
        outputs = {str(row["id"]): row for row in rows}
    summary = run_eval(read_jsonl(base / entry["dataset"]), scorer, key, out / entry["name"],
                       threshold=entry["threshold"], outputs=outputs, default_run=entry["run"],
                       created_at=when)  # fmt: skip
    items, passed = summary["items"], summary["passed"]
    rate = Decimal(passed) / Decimal(items) if items else Decimal(0)
    ok = items > 0 and rate >= Decimal(str(entry["min_pass_rate"]))
    return {"name": entry["name"], "eval": summary["eval"], "dir": (out / entry["name"]).as_posix(),
            "items": items, "passed": passed, "mean_score": summary["mean_score"],
            "pass_rate": float(rate), "min_pass_rate": entry["min_pass_rate"], "ok": ok,
            "judge_prompt": link}  # fmt: skip


def run_ci(
    config: Path, key: Any, out: Path, *, repo_path: Path, created_at: str | None = None
) -> dict[str, Any]:
    """Run every eval *config* declares; ``ok`` only when each one passes its gate."""
    from opentine.repository import Repo

    entries = load(config)
    base = repo_path
    repo = None
    if any(entry["judge_prompt"] for entry in entries):
        repo = Repo.open(repo_path)
    rows = [_one(entry, base, key, out, repo, created_at) for entry in entries]
    return {"config": config.as_posix(), "out": out.as_posix(),
            "ok": all(row["ok"] for row in rows), "evals": rows}  # fmt: skip


__all__ = ["CONFIG", "ConfigError", "judge_template", "load", "run_ci"]
