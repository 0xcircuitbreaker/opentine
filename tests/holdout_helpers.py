"""Shared fixtures for the 0.61 sealed-holdout tests (deterministic keys, no sleeps).

``hold(tmp_path)`` makes a repository whose owner-pinned key roles name a
``dataset`` key, an ``eval`` key and an ``optimizer`` key, writes the item file
and the key files, and returns a :class:`Hold` that drives ``tine dataset``.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentine import _schemas, cli
from opentine.repository import Repo
from tests.key_roles_helpers import pin_roles
from tests.promote_helpers import AT, fingerprint, write_key

DATASET, EVAL, OPTIMIZER = "1d" * 32, "2e" * 32, "3f" * 32
ITEMS = [{"id": f"h-{i:02d}", "input": f"holdout question number {i} about the quiet violet "
          f"lighthouse keeper {i}", "expected": f"sealed answer {i} zebra quartz"}
         for i in range(6)]  # fmt: skip


def tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    row = json.loads(out) if out.strip().startswith("{") else {}
    if row:
        assert _schemas.validate_output(row) == [], row
    return code, row


class Hold:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "repo"
        self.repo = Repo.init(self.root)
        roles = {"dataset": [fingerprint(DATASET)], "eval": [fingerprint(EVAL)],
                 "optimizer": [fingerprint(OPTIMIZER)]}  # fmt: skip
        lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
        (self.repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode())
        pin_roles(self.repo.path)
        self.keys = {seed: write_key(base / f"{seed[:2]}.key", seed).as_posix()
                     for seed in (DATASET, EVAL, OPTIMIZER)}  # fmt: skip
        self.seal_key = (base / "secret" / "seal.key").as_posix()
        self.items = base / "items.jsonl"
        with open(self.items, "w", encoding="utf-8", newline="\n") as handle:
            handle.writelines(json.dumps(item, sort_keys=True) + "\n" for item in ITEMS)

    def folder(self, name: str = "h1") -> Path:
        return self.root / ".tine" / "holdouts" / name

    def seal(self, capsys, name: str = "h1", *extra: str, unseals: int = 2,
             items: int = 4, seed: str = DATASET) -> tuple[int, dict]:  # fmt: skip
        return tine(capsys, "dataset", "seal", self.items.as_posix(), "--out",
                    self.folder(name).as_posix(), "--name", name, "--max-unseals", str(unseals),
                    "--max-items", str(items), "--key", self.keys[seed], "--seal-key",
                    self.seal_key, "--repo", self.root.as_posix(), "--at", AT, "--json",
                    *extra)  # fmt: skip

    def unseal(self, capsys, *extra: str, name: str = "h1", seed: str = EVAL,
               run: str = "run-eval", out: str = "released.jsonl") -> tuple[int, dict]:  # fmt: skip
        return tine(capsys, "dataset", "unseal", self.folder(name).as_posix(), "--out",
                    (self.base / "out" / out).as_posix(), "--run", run, "--why", "scoring",
                    "--key", self.keys[seed], "--seal-key", self.seal_key, "--repo",
                    self.root.as_posix(), "--at", AT, "--json", *extra)  # fmt: skip


def codes(row: dict) -> set[str]:
    return {item["code"] for item in row.get("refusals", [])}


__all__ = ["DATASET", "EVAL", "ITEMS", "OPTIMIZER", "Hold", "codes", "tine"]
