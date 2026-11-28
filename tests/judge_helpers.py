"""Shared fixtures for the 0.89 judge-assurance tests: pinned keys, items, fake judges."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _eval_judge
from opentine.repository import Repo
from tests.key_roles_helpers import pin_roles
from tests.promote_helpers import fingerprint

REV1, REV2, SCORER, OPTIMIZER, OTHER = "a1" * 32, "a2" * 32, "5a" * 32, "7c" * 32, "22" * 32
BOTH = "b3" * 32  # pinned reviewer *and* optimizer: grants nothing
AT = "2026-12-01T10:00:00Z"


def write_jsonl(path: Path, rows: list) -> Path:
    path.write_bytes("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode("utf-8"))
    return path


class Fake:
    """A model whose reply is a function of the prompt text (no network)."""

    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    async def complete(self, messages, **_):
        self.calls += 1
        return {"text": self.reply(messages[0]["content"])}


def fake_models(monkeypatch, replies: dict) -> dict:
    """``_eval_judge._model`` returns ``Fake(replies[spec])``; the fakes by spec."""
    made = {spec: Fake(reply) for spec, reply in replies.items()}
    monkeypatch.setattr(_eval_judge, "_model", lambda spec, *_a: made[spec])
    return made


@pytest.fixture(name="room")
def judge_room(tmp_path: Path, monkeypatch) -> dict:
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    repo = Repo.init(tmp_path / "r")
    roles = {"reviewer": [fingerprint(REV1), fingerprint(REV2), fingerprint(BOTH)],
             "scorer": [fingerprint(SCORER)],
             "optimizer": [fingerprint(OPTIMIZER), fingerprint(BOTH)]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{r} = {json.dumps(k)}\n" for r, k in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    for seed in (REV1, REV2, SCORER, OPTIMIZER, OTHER, BOTH):
        (tmp_path / f"{seed[:2]}.key").write_bytes(seed.encode("ascii"))
    (tmp_path / "rubric.md").write_bytes(b"pass only when the answer is exactly right\n")
    items = [{"id": f"i{n}", "input": f"q{n}", "expected": "x", "output": f"answer {n}"}
             for n in range(20)]  # fmt: skip
    write_jsonl(tmp_path / "items.jsonl", items)
    return {"base": tmp_path, "repo": repo, "items": items}


def keyfile(room: dict, seed: str) -> str:
    return (room["base"] / f"{seed[:2]}.key").as_posix()


__all__ = ["AT", "BOTH", "Fake", "OPTIMIZER", "OTHER", "REV1", "REV2", "SCORER", "fake_models",
           "judge_room", "keyfile", "write_jsonl"]  # fmt: skip
