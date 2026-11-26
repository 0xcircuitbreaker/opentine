"""0.84: sealed episode segments, inclusion proofs and commit-then-reveal sampling audits."""

from __future__ import annotations

import json
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import (
    _ingest_batch,
    _ingest_policy,
    _rl_audit,
    _rl_merkle,
    _rl_segment,
    _rl_verify,
    _schemas,
    cli,
)
from opentine._ingest_policy import IngestError
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo, _oplog
from opentine.repository._holds import INGEST_AUDIT, INGEST_SEGMENT, HoldError, release
from opentine.repository._tlog import leaf_hash, merkle_root
from opentine.repository._tlog_proof import inclusion_proof, verify_inclusion
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"runner": 31, "policy": 32, "optimizer": 33, "auditor": 34, "stranger": 35}
T0 = 1_800_000_000_000


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


def _episodes(n: int, start: int = 0) -> bytes:
    return b"".join(json.dumps({"kind": "episode", "n": start + i, "r": (start + i) % 7}).encode()
                    + b"\n" for i in range(n))  # fmt: skip


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


def make_repo(tmp_path, monkeypatch):
    """A repository with pinned runner, policy, optimizer and auditor keys and a rate-1 policy."""
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    for name in SEEDS:
        (tmp_path / f"{name}.key").write_bytes(bytes([SEEDS[name]]).hex().encode() * 32)
    roles = {r: [_fpr(r)] for r in ("runner", "policy", "optimizer", "auditor")}
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    doc = _ingest_policy.build("rl", capture=[], drop=[], rate=1.0, seed="cd" * 32,
                               issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    _ingest_policy.record(repo, doc, _key("policy"))
    return repo


@pytest.fixture
def repo(tmp_path, monkeypatch):
    return make_repo(tmp_path, monkeypatch)


def _fill(repo, batches: int = 3, size: int = 100) -> list[dict]:
    return [_ingest_batch.append(repo, "rl", _episodes(size, size * i), _key("runner"),
                                 at_ms=T0 + i) for i in range(batches)]  # fmt: skip


def _advance(repo) -> None:
    """Any later op log entry: the seed's checkpoint must follow the seal."""
    entry = _oplog._Op("tine test", None)
    entry.note = "later"
    _oplog.record(repo.path, entry, [])


def test_tree_proofs_match_rfc6962_for_every_size_and_position():
    for size in range(1, 34):
        leaves = [leaf_hash(bytes([i])) for i in range(size)]
        tree = _rl_merkle.Tree(leaves)
        assert tree.root() == merkle_root(leaves)
        for position in range(size):
            verify_inclusion(leaves[position], position, size,
                             inclusion_proof(tree, position), tree.root())  # fmt: skip


def test_sample_size_is_the_smallest_n_meeting_the_exact_hypergeometric_bound():
    conf, bad = Fraction(99, 100), Fraction(5, 1000)
    for population in (1, 50, 199, 200, 201, 1000, 10_000, 1_000_000):
        row = _rl_merkle.sample_size(population, conf, bad)
        b = row["threshold"]
        assert b == population * 5 // 1000 + 1

        def miss(n, population=population, b=b):
            value = Fraction(1)
            for i in range(n):
                value *= Fraction(population - b - i, population - i)
            return value

        n = row["sample"]
        if b > population:
            assert n == 0
            continue
        assert miss(n) <= Fraction(1, 100) and (n == 0 or miss(n - 1) > Fraction(1, 100))
        assert row["miss_probability"] <= 0.01
    # the binomial (with replacement) bound is an upper bound on the exact sample size
    assert _rl_merkle.sample_size(1_000_000, conf, bad)["sample"] <= 919


def test_samples_are_distinct_in_range_and_a_pure_function_of_the_seed():
    one = _rl_merkle.sample("ab" * 32, 1000, 300)
    assert one == _rl_merkle.sample("ab" * 32, 1000, 300)
    assert len(set(one)) == 300 and all(0 <= p < 1000 for p in one) and one == sorted(one)
    assert one != _rl_merkle.sample("ac" * 32, 1000, 300)
    assert _rl_merkle.sample("ab" * 32, 10, 10) == list(range(10))


def test_seal_roots_the_batches_and_commits_in_the_op_log(repo):
    batches = _fill(repo)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + 10)
    assert segment["batches"] == [b["id"] for b in batches]
    assert segment["episodes"] == 300 and (segment["first_index"], segment["next_index"]) == (
        0,
        300,
    )
    lines = [ln.encode() for b in batches
             for ln in repo.get(b["id"]).payload()["value"]["events"].splitlines()]  # fmt: skip
    assert segment["root"] == "sha256:" + merkle_root([leaf_hash(x) for x in lines]).hex()
    ops = _oplog.read_ops(repo.path)
    assert ops[segment["log"]["index"]]["note"] == _rl_segment.note_text(
        "rl", 0, segment["root"], batches[-1]["id"]
    )
    # the next segment continues the chain; nothing new to seal is refused
    with pytest.raises(IngestError, match="no batch to seal"):
        _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + 11)
    more = _ingest_batch.append(repo, "rl", _episodes(50, 300), _key("runner"), at_ms=T0 + 12)
    second = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + 13)
    assert second["seq"] == 1 and second["previous"] == segment["id"]
    assert second["batches"] == [more["id"]] and second["first_index"] == 300


def test_seal_refuses_optimizer_unpinned_and_unknown_keys(repo):
    _fill(repo, 1)
    for name in ("optimizer", "stranger", "auditor"):
        with pytest.raises(IngestError, match="may not seal"):
            _rl_segment.seal(repo, "rl", _key(name), at_ms=T0)


def test_audit_seed_needs_a_checkpoint_strictly_after_the_seal(repo):
    _fill(repo)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + 10)
    with pytest.raises(IngestError, match="not later than the seal"):
        _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                      max_bad="0.005", at_ms=T0 + 20)  # fmt: skip
    log = _oplog.log_root(repo.path)
    early = (log / "checkpoint").read_bytes()
    _advance(repo)
    with pytest.raises(IngestError, match="not later than the seal"):
        _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                      max_bad="0.005", at_ms=T0 + 20, checkpoint=early)  # fmt: skip
    middle = (log / "checkpoint").read_bytes()
    _advance(repo)
    later = (log / "checkpoint").read_bytes()
    row = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                        max_bad="0.005", at_ms=T0 + 20)  # fmt: skip
    # the seed comes from the first tree after the seal, whichever later checkpoint proves it
    pub = _key("auditor").public_key().public_bytes_raw()
    again = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005",
                               checkpoint=middle, reveal=(row["reveal"], pub))  # fmt: skip
    assert again["seed"] == row["seed"] and row["checkpoint"]["size"] == row["checkpoint"][
        "seal_index"] + 2 and row["checkpoint"]["note"] == later.decode()  # fmt: skip
    assert row["verdict"] == "pass" and row["checked"] == row["ok"] == row["bound"]["sample"]
    assert (row["bound"]["tolerated"], row["checked"]) == (1, 270)  # 2 bad of 300 caught at 99%


def test_a_checkpoint_that_disagrees_with_the_log_is_ambiguous_and_refused(repo, tmp_path):
    from opentine.repository._tlog_note import _signer, sign_checkpoint

    _fill(repo)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + 10)
    _advance(repo)
    _advance(repo)
    log = _oplog.log_root(repo.path)
    fork = sign_checkpoint(_signer(log, _oplog.ORIGIN), _oplog.ORIGIN,
                           segment["log"]["index"] + 3, b"\x07" * 32)  # fmt: skip
    with pytest.raises(IngestError, match="ambiguous"):
        _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                      max_bad="0.005", at_ms=T0, checkpoint=fork)  # fmt: skip
    ahead = sign_checkpoint(_signer(log, _oplog.ORIGIN), _oplog.ORIGIN, 10_000, b"\x07" * 32)
    with pytest.raises(IngestError, match="ambiguous"):
        _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                      max_bad="0.005", at_ms=T0, checkpoint=ahead)  # fmt: skip


def test_audit_signers_must_be_pinned_auditors_never_optimizers(repo):
    _fill(repo, 1)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0)
    _advance(repo)
    for name in ("optimizer", "runner", "stranger"):
        with pytest.raises(IngestError, match="may not sign audits"):
            _rl_audit.run(repo, segment["id"], _key(name), confidence="0.99",
                          max_bad="0.005", at_ms=T0)  # fmt: skip


def test_proofs_are_self_contained_and_detect_an_altered_line(repo):
    batches = _fill(repo, 2)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0)
    doc = _rl_audit.prove(repo, segment["id"], 137)
    line = repo.get(batches[1]["id"]).payload()["value"]["events"].splitlines()[37].encode()
    assert json.loads(line)["i"] == 137
    assert _rl_audit.check_proof(doc, line)
    assert not _rl_audit.check_proof(doc, line.replace(b'"r":4', b'"r":5'))
    with pytest.raises(IngestError, match="not a captured episode"):
        _rl_audit.prove(repo, segment["id"], 5000)


def test_segments_verify_recomputes_and_holds_are_never_released(repo):
    _fill(repo)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0)
    report = _rl_verify.verify(repo, "rl")
    assert report["ok"] and {f["code"] for f in report["findings"]} == {"ingest.segment-unaudited"}
    _advance(repo)
    audit = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.9",
                          max_bad="0.01", at_ms=T0)  # fmt: skip
    report = _rl_verify.verify(repo, "rl")
    assert report["ok"] and report["findings"] == [], report["findings"]
    assert report["segments"][0]["audits"] == [audit["id"]] and report["episodes"] == 300
    for target in (INGEST_SEGMENT + "rl", INGEST_AUDIT + segment["id"]):
        with pytest.raises(HoldError, match="never released"):
            release(repo, target)


def test_cli_seal_audit_prove_segments_round_trip(repo, capsys, tmp_path):
    batch = tmp_path / "b.jsonl"
    batch.write_bytes(_episodes(120))
    assert _tine(capsys, "ingest", "--batch", batch.as_posix(), "--stream", "rl", "--key",
                 "runner.key", "--repo", "r", "--json")[0] == 0  # fmt: skip
    code, out = _tine(capsys, "ingest", "seal", "--stream", "rl", "--key", "runner.key",
                      "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and out["command"] == "ingest seal" and out["segment"]["episodes"] == 120
    seg = out["segment"]["id"]
    _advance(Repo.open(tmp_path / "r"))
    code, out = _tine(capsys, "ingest", "audit", seg, "--key", "auditor.key", "--confidence",
                      "0.95", "--max-bad", "0.02", "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and out["audit"]["verdict"] == "pass", out
    code, out = _tine(capsys, "ingest", "prove", seg, "--index", "7", "--repo", "r", "--json")
    assert code == 0 and out["proof"]["position"] == 7
    code, out = _tine(capsys, "ingest", "segments", "rl", "--repo", "r", "--json")
    assert code == 0 and out["report"]["ok"]
