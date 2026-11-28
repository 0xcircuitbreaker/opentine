"""Shared set-up for the 0.91 fleet stop tests: repositories, pinned roles, a channel, a clock.

Every key is a fixed seed. ``STOPPER`` holds the ``stopper`` role, ``POLICY``
the ``policy`` role, ``RUNNER`` the ``runner`` role and ``OPT`` the
``optimizer`` role, all pinned through the owner-signed trust bundle of
:mod:`tests.key_roles_helpers`. Times come from :class:`Clock`, never the wall.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentine import _stop_ops, _stop_policy
from opentine._stop_proof import parse_at
from opentine.repo import Repo
from tests.key_roles_helpers import pin_roles
from tests.promote_helpers import fingerprint, key, write_key

STOPPER, POLICY, RUNNER, OPT, OTHER = "71" * 32, "72" * 32, "73" * 32, "74" * 32, "75" * 32
FLEET = "fleet-a"
T0 = "2026-12-01T09:00:00Z"


class Clock:
    """Milliseconds since the epoch, moved only by the test."""

    def __init__(self, at: str = T0) -> None:
        self.ms = parse_at(at)

    def __call__(self) -> int:
        return self.ms

    def advance(self, seconds: float) -> int:
        self.ms += int(seconds * 1000)
        return self.ms


def roles_text(*, stopper=(STOPPER,), policy=(POLICY,), runner=(RUNNER,), optimizer=(OPT,)) -> str:
    rows = {"stopper": stopper, "policy": policy, "runner": runner, "optimizer": optimizer}
    lines = ["version = 1", "[roles]"]
    lines += [f"{role} = {json.dumps([fingerprint(s) for s in seeds])}"
              for role, seeds in rows.items() if seeds]  # fmt: skip
    return "\n".join(lines) + "\n"


def make_repo(path: Path, *, pinned: bool = True, **roles) -> Repo:
    repo = Repo.init(path)
    store = Path(repo.path)
    (store / "key-roles.toml").write_bytes(roles_text(**roles).encode("utf-8"))
    if pinned:
        pin_roles(store)
    return repo


def fleet(tmp_path: Path, count: int = 1, *, window_s: int = 300, watchdog_s: int = 10,
          pinned: bool = True) -> tuple[Path, list[Repo]]:  # fmt: skip
    """*count* repositories sharing one stop channel, each with the policy installed."""
    from opentine import _stop_channel

    channel = tmp_path / "channel"
    vkey = _stop_channel.init(channel, FLEET)
    repos = []
    for i in range(count):
        repo = make_repo(tmp_path / f"repo{i}", pinned=pinned)
        doc = _stop_policy.make(FLEET, channel.as_posix(), vkey, window_s=window_s,
                                watchdog_s=watchdog_s)  # fmt: skip
        _stop_policy.install(repo, doc)
        repos.append(repo)
    return channel, repos


def keep_going(repo: Repo, channel: Path, runs: list[str], clock: Clock, *, seed: str = STOPPER,
               window_s: int = 300) -> list[dict]:  # fmt: skip
    return _stop_ops.issue_continue(repo, channel, FLEET, runs, key(seed), window_s=window_s,
                                    now_ms=clock())  # fmt: skip


def halt_fleet(repo: Repo, channel: Path, clock: Clock, seed: str = STOPPER) -> dict:
    return _stop_ops.issue_stop(repo, channel, FLEET, key(seed), reason="test stop",
                                now_ms=clock())  # fmt: skip


def key_file(tmp_path: Path, seed: str, name: str) -> Path:
    return write_key(tmp_path / f"{name}.key", seed)


__all__ = ["FLEET", "OPT", "OTHER", "POLICY", "RUNNER", "STOPPER", "Clock", "fleet", "halt_fleet",
           "keep_going", "key", "key_file", "make_repo", "roles_text"]  # fmt: skip
