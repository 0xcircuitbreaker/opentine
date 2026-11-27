"""0.77: batched streaming ingest: signed sampling policies and a chained batch log."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _ingest_batch, _ingest_holds, _ingest_policy, _ingest_verify, _schemas, cli
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import INGEST_HEAD, HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"runner": 21, "policy": 22, "optimizer": 23, "stranger": 24}
SEED = "ab" * 32
T0 = 1_800_000_000_000


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


def _events(n: int, start: int = 0, kind: str = "step") -> bytes:
    return b"".join(json.dumps({"kind": kind, "n": start + i}).encode() + b"\n" for i in range(n))


def _tine(capsys, *argv: str) -> tuple[int, dict]:
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


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    for name in SEEDS:
        (tmp_path / f"{name}.key").write_bytes(bytes([SEEDS[name]]).hex().encode() * 32)
    roles = {"runner": [_fpr("runner")], "policy": [_fpr("policy")],
             "optimizer": [_fpr("optimizer")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    return repo


def _policy(repo, signer: str = "policy", rate: float = 0.5, **kw) -> str:
    doc = _ingest_policy.build("rl", capture=kw.get("capture", []), drop=kw.get("drop", []),
                               rate=rate, seed=SEED, issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    return _ingest_policy.record(repo, doc, _key(signer))


def _codes(report: dict) -> set[str]:
    return {f["code"] for f in report["findings"] if f["level"] == "fail"}


def test_batches_chain_and_verify_with_recomputable_sampling(repo):
    _policy(repo, rate=0.5, drop=["debug"])
    rows = [_ingest_batch.append(repo, "rl", _events(200, 200 * i) + _events(5, kind="debug"),
                                 _key("runner"), at_ms=T0 + i) for i in range(3)]  # fmt: skip
    assert [r["seq"] for r in rows] == [0, 1, 2]
    assert [r["previous"] for r in rows] == [None, rows[0]["id"], rows[1]["id"]]
    assert [r["first_index"] for r in rows] == [0, 205, 410]
    for row in rows:
        assert row["captured"] + row["dropped"] == row["received"] == 205
        assert row["dropped_by"]["kind"] == 5 and 0 < row["captured"] < 200
    report = _ingest_verify.verify(repo, "rl")
    assert report["ok"], report["findings"]
    assert report["batches"] == 3 and report["received"] == 615
    assert report["head"] == rows[-1]["id"] and report["roles"] == "pinned"
    # the decision is a pure function of the signed seed and the index
    stored = repo.get(rows[0]["id"]).payload()["value"]["events"].splitlines()
    picked = [json.loads(line)["i"] for line in stored]
    policy = _ingest_batch.current_policy(repo, "rl")["claim"]
    assert picked == [i for i in range(200) if _ingest_policy.decide(policy, i, "step") is None]


def test_one_durability_point_per_batch_before_the_head_moves(repo, monkeypatch):
    from opentine.repository import _write_batch

    _policy(repo, rate=1.0)
    flushes: list[tuple[list[str], str | None]] = []
    real = _write_batch.flush

    def flush(target):
        staged = sorted(_write_batch.staged(target) or {})
        flushes.append((staged, _ingest_holds.head(target, "rl")))
        return real(target)

    monkeypatch.setattr(_write_batch, "flush", flush)
    row = _ingest_batch.append(repo, "rl", _events(50), _key("runner"), at_ms=T0)
    assert len(flushes) == 1 and row["id"] in flushes[0][0]
    assert flushes[0][1] is None  # the head had not moved when the batch was made durable
    assert _ingest_holds.head(repo, "rl") == row["id"]


@pytest.mark.parametrize("signer,code", [("optimizer", "ingest.policy-optimizer-key"),
                                         ("stranger", "ingest.policy-role")])  # fmt: skip
def test_policy_from_an_unpinned_or_optimizer_key_fails(repo, signer, code, monkeypatch):
    oid = _policy(repo, signer=signer)
    for kw in ({}, {"policy_id": oid}):  # refused at write time
        with pytest.raises(_ingest_policy.IngestError, match="policy"):
            _ingest_batch.append(repo, "rl", _events(10), _key("runner"), at_ms=T0, **kw)
    monkeypatch.setattr(_ingest_batch, "_refusal", lambda row, roles: None)  # a forged writer
    _ingest_batch.append(repo, "rl", _events(10), _key("runner"), at_ms=T0)
    report = _ingest_verify.verify(repo, "rl")
    assert not report["ok"] and code in _codes(report)


def test_a_newer_policy_from_an_unroled_key_never_takes_effect(repo):
    owner = _policy(repo, drop=[])
    doc = _ingest_policy.build("rl", capture=[], drop=["step"], rate=1.0, seed=SEED,
                               issued_at="2099-01-01T00:00:00Z")  # fmt: skip
    _ingest_policy.record(repo, doc, _key("stranger"))
    assert _ingest_batch.current_policy(repo, "rl")["id"] == owner
    row = _ingest_batch.append(repo, "rl", _events(10), _key("runner"), at_ms=T0)
    assert row["policy"] == owner and row["dropped_by"]["kind"] == 0


def test_unpinned_roles_fail_closed(repo, tmp_path, monkeypatch):
    _policy(repo)
    _ingest_batch.append(repo, "rl", _events(10), _key("runner"), at_ms=T0)
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "elsewhere").as_posix())
    report = _ingest_verify.verify(repo, "rl")
    assert "ingest.policy-unpinned" in _codes(report)


def test_no_policy_refuses_the_batch(repo):
    with pytest.raises(_ingest_policy.IngestError, match="no signed sampling policy"):
        _ingest_batch.append(repo, "rl", _events(3), _key("runner"), at_ms=T0)


def _forge(repo, row: dict, **changes) -> str:
    """Re-sign a batch claim with changes, as a writer with a valid key could."""
    stored = repo.get(row["id"]).payload()
    claim = stored["value"] | changes
    return _ingest_holds.write(repo, stored["target_id"], claim, _key("runner"),
                               previous=claim["previous"], signed_at=claim["at"])  # fmt: skip


def _set_head(repo, oid: str) -> None:
    from opentine.repository._holds import edit_holds, holds_path

    target = INGEST_HEAD + "rl"
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r["target"] != target),
                                               {"oid": oid, "target": target}])  # fmt: skip


def test_drop_reorder_and_replay_are_detected(repo):
    _policy(repo, rate=1.0)
    rows = [_ingest_batch.append(repo, "rl", _events(4, 4 * i), _key("runner"), at_ms=T0)
            for i in range(3)]  # fmt: skip
    # drop: the third batch skips the second (previous points at the first)
    _set_head(repo, _forge(repo, rows[2], previous=rows[0]["id"]))
    assert "ingest.chain-order" in _codes(_ingest_verify.verify(repo, "rl"))
    # replay: the second batch's claim appended again after the third
    _set_head(repo, _forge(repo, rows[1], previous=rows[2]["id"]))
    assert "ingest.chain-order" in _codes(_ingest_verify.verify(repo, "rl"))
    # counts: a batch claiming fewer drops than it made
    _set_head(repo, _forge(repo, rows[2], captured=3))
    assert "ingest.counts" in _codes(_ingest_verify.verify(repo, "rl"))
    _set_head(repo, rows[2]["id"])
    assert _ingest_verify.verify(repo, "rl")["ok"]


def test_sampling_lie_is_detected(repo):
    _policy(repo, rate=0.3)
    row = _ingest_batch.append(repo, "rl", _events(40), _key("runner"), at_ms=T0)
    policy = _ingest_batch.current_policy(repo, "rl")["claim"]
    every = "".join(json.dumps({"e": {"kind": "step", "n": i}, "i": i, "k": "step"}) + "\n"
                    for i in range(40))  # fmt: skip
    assert any(_ingest_policy.decide(policy, i, "step") for i in range(40))
    _set_head(repo, _forge(repo, row, events=every, captured=40, dropped=0,
                           dropped_by={"kind": 0, "rate": 0}))  # fmt: skip
    assert "ingest.sampling" in _codes(_ingest_verify.verify(repo, "rl"))


def test_holds_are_never_released(repo):
    _policy(repo)
    _ingest_batch.append(repo, "rl", _events(3), _key("runner"), at_ms=T0)
    with pytest.raises(HoldError, match="never released"):
        release(repo, INGEST_HEAD + "rl")
    assert _ingest_holds.streams(repo) == ["rl"]


def test_concurrent_writer_cannot_fork_the_chain(repo):
    _policy(repo, rate=1.0)
    first = _ingest_batch.append(repo, "rl", _events(2), _key("runner"), at_ms=T0)
    with pytest.raises(_ingest_policy.IngestError, match="moved"):
        _ingest_holds.move_head(repo, "rl", None, first["id"])


def test_hostile_lines_are_refused():
    with pytest.raises(_ingest_policy.IngestError):
        _ingest_batch.parse(b"[" * 5000 + b"\n")
    with pytest.raises(_ingest_policy.IngestError):
        _ingest_batch.parse(b'{"kind": "bad kind!"}\n')
    with pytest.raises(_ingest_policy.IngestError):
        _ingest_batch.parse(b"[1]\n")
    assert _ingest_batch.parse(b'\n{"type": "episode"}\n\n') == [("episode", {"type": "episode"})]


def test_cli_policy_batch_verify(repo, tmp_path, capsys):
    code, body = _tine(capsys, "ingest", "policy", "--stream", "rl", "--rate", "0.5", "--seed",
                       SEED, "--key", "policy.key", "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and body["policy"]["seed_source"] == "operator"
    (tmp_path / "b.jsonl").write_bytes(_events(30))
    code, body = _tine(capsys, "ingest", "--batch", "b.jsonl", "--stream", "rl", "--key",
                       "runner.key", "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and body["batch"]["received"] == 30
    code, body = _tine(capsys, "ingest", "verify", "rl", "--repo", "r", "--json")
    assert code == 0 and body["report"]["ok"]
    code, body = _tine(capsys, "ingest", "verify", "other", "--repo", "r", "--json")
    assert code == 1 and "ingest.policy-missing" in _codes(body["report"])
