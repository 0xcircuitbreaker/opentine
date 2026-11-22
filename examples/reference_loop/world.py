"""Set up the loop's repository: keys, the owner-pinned trust bundle and every policy.

Each key has one job. The **owner** key signs the trust bundle that names the
roles; it is pinned outside the repository (``OPENTINE_TRUST_OWNER``), so the
loop cannot grant itself a role by editing ``.tine/key-roles.toml``. The
**optimizer** key is the loop's own key and holds the ``optimizer`` role: it
signs nothing that counts, and every gate refuses it where it tries. The
**policy**, **runner**, **eval**, **dataset**, **curator**, **monitor**,
**promoter** and three **approver** keys belong to the people and services
around the loop.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from reference_loop import toy
from reference_loop.tine import must

NAMES = ("owner", "optimizer", "policy", "runner", "eval", "dataset", "curator", "monitor",
         "promoter", "a1", "a2", "a3")  # fmt: skip
OWNER_NAME = "example.com/reference-loop"
LOOP, SUBJECT, LABEL = "reference", "loop:reference", "prod"
SANDBOX = {"network_allowlist": [], "mounts": [{"path": "sandbox/", "mode": "rw"}],
           "privileges": ["no-new-privileges"], "image_digest": "sha256:" + "0" * 64,
           "seccomp_digest": "sha256:" + "1" * 64}  # fmt: skip
MONITOR = {"id": "protected-writes", "rules": [
    {"tool": "write", "pattern": "grader/|tests/|sandbox\\.json|\\.tine/", "score": 0.9,
     "action": "flag"}]}  # fmt: skip


class Clock:
    """An injected clock: every record time comes from here, one minute apart."""

    def __init__(self, start: str = "2026-12-01T09:00:00Z") -> None:
        self.now = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

    def tick(self) -> str:
        self.now += timedelta(minutes=1)
        return self.now.strftime("%Y-%m-%dT%H:%M:%SZ")

    def ms(self) -> int:
        return int(self.now.timestamp() * 1000)


@dataclass
class World:
    work: Path
    keys: dict[str, str] = field(default_factory=dict)
    fps: dict[str, str] = field(default_factory=dict)
    owner_vkey: str = ""
    clock: Clock = field(default_factory=Clock)
    files: dict[str, str] = field(default_factory=dict)

    @property
    def root(self) -> Path:
        return self.work / "repo"

    @property
    def repo(self) -> str:
        return self.root.as_posix()

    def path(self, *parts: str) -> Path:
        return self.work.joinpath(*parts)


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path.as_posix()


def make_keys(world: World) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine._signing_pins import key_fingerprint
    from opentine.repository._tlog_note import vkey_for

    for name in NAMES:
        key = Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes_raw()
        world.keys[name] = _write(world.path("keys", f"{name}.key"), key.private_bytes_raw().hex())
        os.chmod(world.keys[name], 0o600)  # private keys: owner-only
        world.fps[name] = key_fingerprint(raw)
        if name == "owner":
            world.owner_vkey = vkey_for(OWNER_NAME, raw)


def roles(world: World) -> dict[str, list[str]]:
    f = world.fps
    return {"optimizer": [f["optimizer"]], "policy": [f["policy"]], "runner": [f["runner"]],
            "eval": [f["eval"]], "scorer": [f["eval"]], "dataset": [f["dataset"]],
            "curator": [f["curator"]], "monitor": [f["monitor"]],
            "approver": [f["a1"], f["a2"], f["a3"]]}  # fmt: skip


def trust(world: World) -> None:
    """Sign the roles into ``.tine/trust-bundle.note`` with the owner key."""
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles(world).items()]
    path = _write(world.root / ".tine" / "key-roles.toml", "\n".join(lines) + "\n")
    must("trust", "bundle", "create", "--key", world.keys["owner"], "--name", OWNER_NAME,
         "--serial", "1", "--pin", world.fps["policy"], "--key-roles", path, "--out",
         (world.root / ".tine" / "trust-bundle.note").as_posix(), "--json")  # fmt: skip


def protect(world: World) -> None:
    """The protected surfaces (grader, tests, sandbox policy), pinned and signed."""
    text = (
        'version = 1\n\n[[surface]]\nname = "grader"\nkind = "grader"\nglobs = ["grader/**"]\n'
        '\n[[surface]]\nname = "tests"\nkind = "test"\nglobs = ["tests/**"]\n'
        '\n[[surface]]\nname = "sandbox"\nkind = "sandbox"\nglobs = ["sandbox.json"]\n'
    )
    _write(world.root / ".tine" / "protected.toml", text)
    must("integrity", "pin", "--repo", world.repo, "--json")
    must("integrity", "sign", "--key", world.keys["policy"], "--at", world.clock.tick(),
         "--repo", world.repo, "--json")  # fmt: skip


def promotion_policy(world: World) -> None:
    f = world.fps
    admission = {"kind": "opentine.admission-policy", "version": 1, "refs": ["labels/*"],
                 "subjects": [f["promoter"]], "levels": ["OPENTINE_PROMOTED"]}  # fmt: skip
    _write(world.path("policy", "labels.json"), json.dumps(admission))
    values: dict[str, Any] = {
        "label_policy": "labels.json", "test": "paired-bootstrap", "alpha": "0.05", "seed": 7,
        "resamples": 500, "min_n": 30, "metric": "pass_rate", "budget_usd": "10",
        "approvers": [f["a1"], f["a2"], f["a3"]], "min_approvals": 2,
        "require_holdout": True, "eval_signers": [f["eval"]]}  # fmt: skip
    lines = ["[promote]"] + [f"{k} = {json.dumps(v)}" for k, v in values.items()]
    world.files["promote"] = _write(world.path("policy", "promote.toml"), "\n".join(lines) + "\n")
    world.files["promote_sig"] = world.path("policy", "promote.sig.json").as_posix()
    must("promote", world.files["promote"], "--sign-policy", "--key", world.keys["policy"],
         "--out", world.files["promote_sig"], "--at", world.clock.tick(), "--json")  # fmt: skip
    oversight = (f"version = 1\n[tiers.high]\nk = 2\napprovers = "
                 f"{json.dumps([f['a1'], f['a2'], f['a3']])}\n[[route]]\n"
                 f'source = "promotion"\nlabel = "{LABEL}"\ntier = "high"\n')  # fmt: skip
    _write(world.root / ".tine" / "oversight.toml", oversight)
    must("oversight", "sign-policy", "--key", world.keys["policy"], "--at", world.clock.tick(),
         "--repo", world.repo, "--json")  # fmt: skip


def budget(world: World, cap_usd: float) -> None:
    out = world.path("policy", "budget.json").as_posix()
    must("budget", "sign-policy", SUBJECT, "--serial", "1", "--money-usd", str(cap_usd),
         "--key", world.keys["policy"], "--out", out, "--at", world.clock.tick(),
         "--repo", world.repo, "--json")  # fmt: skip
    must("budget", "apply", out, "--key", world.keys["runner"], "--at", world.clock.tick(),
         "--repo", world.repo, "--json")  # fmt: skip


def holdout(world: World, max_unseals: int) -> None:
    items = toy.items("holdout")
    src = _write(world.path("data", "holdout.jsonl"),
                 "".join(json.dumps(i, sort_keys=True) + "\n" for i in items))  # fmt: skip
    world.files["holdout"] = (world.root / ".tine" / "holdouts" / "h1").as_posix()
    world.files["seal_key"] = world.path("keys", "seal.key").as_posix()
    must("dataset", "seal", src, "--out", world.files["holdout"], "--name", "h1",
         "--max-unseals", str(max_unseals), "--max-items", str(len(items)), "--key",
         world.keys["dataset"], "--seal-key", world.files["seal_key"], "--repo", world.repo,
         "--at", world.clock.tick(), "--json")  # fmt: skip
    Path(src).unlink()  # no plaintext copy of the holdout stays next to the sandboxes


def uplift_suite(world: World, run: str) -> str:
    suite = {"name": "reference-loop-ops", "version": "1", "scoring": "binary",
             "tasks": [{"id": op, "minutes": toy.MINUTES[op]} for op in toy.ORDER]}  # fmt: skip
    path = _write(world.path("policy", "uplift-suite.json"), json.dumps(suite, sort_keys=True))
    body = must("uplift", "suite", path, "--run", run, "--key", world.keys["eval"], "--at",
                world.clock.tick(), "--repo", world.repo, "--json")  # fmt: skip
    world.files["suite"] = body["suite"]
    return body["suite"]


def build(work: Path) -> World:
    """A fresh repository under *work* with every key, policy and pin in place."""
    from opentine.repository import Repo

    world = World(Path(work))
    make_keys(world)
    Repo.init(world.root)
    toy.write_repo(world.root)
    return world


def configure(world: World, *, cap_usd: float, max_unseals: int) -> None:
    """Everything that needs the owner pin in force (call inside ``isolated``)."""
    trust(world)
    protect(world)
    promotion_policy(world)
    budget(world, cap_usd)
    holdout(world, max_unseals)


__all__ = ["LABEL", "LOOP", "MONITOR", "SANDBOX", "SUBJECT", "Clock", "World", "build",
           "configure", "roles", "uplift_suite"]  # fmt: skip
