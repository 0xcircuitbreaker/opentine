"""Shared fixtures for the monitor coverage ledger, heartbeat and operating-point tests."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _ingest_batch, _ingest_policy, _monitors, _schemas, cli
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from tests.key_roles_helpers import pin_roles

SEEDS = {"runner": 31, "policy": 32, "optimizer": 33, "monitor": 34, "scorer": 35,
         "stranger": 36, "monitor2": 37}  # fmt: skip
SEED = "cd" * 32
T0 = 1_800_000_000_000  # ms; every clock in these tests is injected
CONFIG = """version = 1
mode = "advisory"
[monitor]
id = "rules"
kind = "rule"
threshold = 0.5
[[monitor.rules]]
tool = "*"
pattern = "rm -rf"
score = 0.9
category = "destructive"
severity = "high"
[[monitor.rules]]
tool = "*"
pattern = "probe"
score = 0.45
"""


def pin_monitors(repo, signers: dict, required: list | None = None) -> None:
    """Re-sign the trust bundle binding monitor ids to signer keys (0.90)."""
    section = {"version": 1, "signers": signers, **({"required": required} if required else {})}
    pin_roles(repo.path, extra={"monitors": section})


def key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def fpr(name: str) -> str:
    return key_fingerprint(key(name).public_key().public_bytes_raw())


def event(cmd: str, agent: str = "a1", session: str = "s1", run: str = "r1") -> dict:
    return {"kind": "step", "tool": "shell", "arguments": {"cmd": cmd}, "agent": agent,
            "session": session, "run": run}  # fmt: skip


def lines(events: list[dict]) -> bytes:
    return b"".join(json.dumps(e, sort_keys=True).encode("utf-8") + b"\n" for e in events)


def ingest(repo, events: list[dict], at_ms: int) -> dict:
    return _ingest_batch.append(repo, "rl", lines(events), key("runner"), at_ms=at_ms)


def config(text: str = CONFIG) -> dict:
    return _monitors.parse(__import__("tomllib").loads(text))


def tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    body = json.loads(out) if out.strip().startswith("{") else {}
    if body and "error" not in body:
        assert _schemas.validate_output(body) == [], body
    return code, body


@pytest.fixture(name="repo")
def repo_fixture(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    for name in SEEDS:
        (tmp_path / f"{name}.key").write_bytes(bytes([SEEDS[name]]).hex().encode() * 32)
    (tmp_path / "monitor.toml").write_bytes(CONFIG.encode("utf-8"))
    roles = {"runner": [fpr("runner")], "policy": [fpr("policy")],
             "monitor": sorted([fpr("monitor"), fpr("monitor2")]),
             "scorer": [fpr("scorer")], "optimizer": [fpr("optimizer")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_monitors(repo, {"rules": [fpr("monitor")]})
    doc = _ingest_policy.build("rl", capture=[], drop=[], rate=1.0, seed=SEED,
                               issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    _ingest_policy.record(repo, doc, key("policy"))
    return repo
