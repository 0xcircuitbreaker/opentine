"""Shared fixtures for the 0.89 rubric label queue tests (deterministic, no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _judge_provenance as jp
from opentine import _label_ops as ops
from tests.key_roles_helpers import pin_roles
from tests.promote_helpers import fingerprint, key

AT = "2026-11-01T12:00:00Z"
ADMIN, R1, R2, R3, OPT = "1a" * 32, "2b" * 32, "3c" * 32, "4d" * 32, "5e" * 32
RUBRIC = {"name": "helpful", "labels": ["good", "bad"], "instructions": "Is it helpful?"}


def pin(repo: Path, *, reviewers=(R1, R2, R3), optimizer=OPT, extra_reviewers=()) -> None:
    """Pin ADMIN as policy, the reviewers (plus *extra_reviewers*) and the optimizer."""
    store = repo / ".tine"
    store.mkdir(parents=True, exist_ok=True)
    names = [fingerprint(s) for s in (*reviewers, *extra_reviewers)]
    text = (f'version = 1\n[roles]\npolicy = ["{fingerprint(ADMIN)}"]\n'
            f"reviewer = {json.dumps(names)}\n"
            f'optimizer = ["{fingerprint(optimizer)}"]\n')  # fmt: skip
    (store / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(store)


def items(n: int) -> list[dict]:
    return [{"id": f"item-{i:03d}", "text": f"answer {i}"} for i in range(n)]


def write_items(path: Path, rows: list[dict]) -> Path:
    path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))
    return path


def queue(repo: Path, n: int = 4, reviewers=(R1, R2), name: str = "q") -> list[str]:
    """A queue *name* whose *n* items are assigned to *reviewers*; the item digests."""
    from opentine._label_queue import digest

    rubric = repo / "rubric.json"
    rubric.write_bytes(json.dumps(RUBRIC).encode())
    ops.init(repo, name, rubric, key(ADMIN), AT)
    rows = items(n)
    ops.assign(repo, name, write_items(repo / f"{name}-items.jsonl", rows),
               [fingerprint(r) for r in reviewers], key(ADMIN), AT)  # fmt: skip
    return [digest(r) for r in rows]


def provenance(path: Path, prompt: str = "Judge it") -> Path:
    path.write_bytes(json.dumps(jp.build("local:judge", prompt, rubric="r")).encode())
    return path


def outputs(path: Path, rows: list[dict]) -> Path:
    path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))
    return path


@pytest.fixture(name="repo")
def make_repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    pin(root)
    return root


__all__ = ["ADMIN", "AT", "OPT", "R1", "R2", "R3", "RUBRIC", "items", "outputs", "pin",
           "provenance", "queue", "make_repo", "write_items"]  # fmt: skip
