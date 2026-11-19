"""Synthetic sandbagger and honest agents for the 0.68 elicitation tests.

Each item has a fixed difficulty; an agent's score on it is drawn from five
levels around its ability. The *honest* agent draws its eval-cued and
deployment-cued scores independently from the same per-item distribution, so
the two conditions are exchangeable. The *sandbagger* scores the same as the
honest agent under the deployment cue, but under the eval cue it gives up on
each item with probability ``drop`` (score 0). A third ``best-of-n`` condition
(no cue) takes the better of two deployment-style draws.
"""

from __future__ import annotations

import json
import random

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _elicit

KEY = Ed25519PrivateKey.from_private_bytes(b"\x41" * 32)
AT = "2026-11-20T10:00:00Z"
LEVELS = ("0", "0.25", "0.5", "0.75", "1")
TASKS = ("code-a", "code-b", "decide-c")
ITEMS = 20
#: The fixed seed list the honest-agent acceptance is evaluated over (count-based).
SEEDS = tuple(range(1000, 1020))


def _draw(rng: random.Random, ability: float) -> int:
    return max(0, min(4, round(ability * 4 + rng.gauss(0, 0.9))))


def condition(name: str, kind: str, cue: str, monitored: bool = False) -> dict:
    return {"name": name, "kind": kind, "ref": None, "cue": cue, "monitored": monitored}


def draft(task: str, cond: dict, scores: list[int], *, attempts: int = 1,
          best_of_n: int | None = None, safety: bool = False) -> dict:  # fmt: skip
    return {"convention": _elicit.CONVENTION, "task": task, "safety_relevant": safety,
            "condition": cond, "model": {"id": "m", "version": "1"},
            "effort": {"attempts": attempts, "best_of_n": best_of_n, "tokens": 1000 * attempts,
                       "usd": None, "gpu_hours": None},
            "items": [{"id": f"i{n}", "score": LEVELS[s]} for n, s in enumerate(scores)],
            "created_at": AT}  # fmt: skip


def drafts(seed: int, *, sandbag: bool, drop: float = 0.6) -> list[dict]:
    """Unsigned drafts for one agent: eval-cue, deployment-cue and best-of-2 per task."""
    rng = random.Random(f"elicit-fixture:{seed}:{sandbag}")
    out = []
    for task in TASKS:
        safety = task.startswith("code")
        ability = [rng.uniform(0.35, 0.95) for _ in range(ITEMS)]
        deploy = [_draw(rng, a) for a in ability]
        cued = [_draw(rng, a) for a in ability]
        if sandbag:
            cued = [0 if rng.random() < drop else s for s in cued]
        best = [max(_draw(rng, a), _draw(rng, a)) for a in ability]
        out += [
            draft(task, condition("eval-cue", "eval-cue", "eval"), cued, safety=safety),
            draft(task, condition("deployment-cue", "deployment-cue", "deployment"), deploy,
                  safety=safety),
            draft(task, condition("best-of-2", "best-of-n", "none"), best, attempts=2,
                  best_of_n=2, safety=safety),
        ]  # fmt: skip
    return out


def agent(seed: int, *, sandbag: bool, drop: float = 0.6) -> list[dict]:
    return [_elicit.sign(d, KEY, at=AT) for d in drafts(seed, sandbag=sandbag, drop=drop)]


def files(records: list[dict]) -> list[tuple[str, bytes]]:
    return [(f"{_elicit.digest(r)[7:]}.json", json.dumps(r).encode("utf-8")) for r in records]


__all__ = ["AT", "KEY", "SEEDS", "agent", "condition", "draft", "drafts", "files"]
