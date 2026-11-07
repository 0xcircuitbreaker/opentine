"""0.44 X33: opentine-log/1 proofs, witnesses, remote audit transparency, bundle receipts."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _bundle, _transparency, _witness, cli
from opentine.repository import (
    Repo,
    _oplog,
    _remote_tlog,
    _tlog,
    _tlog_cosign,
    _tlog_note,
    _tlog_proof,
    _tlog_receipt,
)
from opentine.repository import client as repository_client
from tests.test_remote_0_12 import URL, _remote, _run

LOG = "example.com/log"


def _log(tmp_path: Path, n: int) -> Path:
    root = tmp_path / "log"
    for i in range(n):
        _tlog_note.append(root, LOG, lambda _e, i=i: f"entry {i}".encode())
    return root


def _vkey(root: Path) -> str:
    return _tlog_note.stored_vkey(root)


# --- RFC 9162 proofs --------------------------------------------------------- #


def test_proofs_round_trip_over_tiles_and_reject_tampering():
    root = Path(tempfile.mkdtemp())
    entries = [str(i).encode() for i in range(600)]
    _tlog.write_tiles(root, entries, 0)
    leaves = [_tlog.leaf_hash(e) for e in entries]
    hashes = _tlog_proof.Hashes(600, lambda rel: (root / rel).read_bytes())
    for n in (1, 2, 3, 7, 8, 255, 256, 257, 513, 600):
        tree = _tlog.merkle_root(leaves[:n])
        assert hashes.range(0, n) == tree
        for i in {0, n // 2, n - 1}:
            proof = _tlog_proof.inclusion_proof(hashes, i, n)
            _tlog_proof.verify_inclusion(leaves[i], i, n, proof, tree)
            if proof:
                with pytest.raises(_tlog.LogError):
                    _tlog_proof.verify_inclusion(leaves[i], i, n, proof[:-1], tree)
        for m in {1, n // 3, n - 1, n}:
            if m:
                old = _tlog.merkle_root(leaves[:m])
                proof = _tlog_proof.consistency_proof(hashes, m, n)
                _tlog_proof.verify_consistency(m, n, old, tree, proof)
                if m < n:
                    with pytest.raises(_tlog.LogError, match="fork"):
                        _tlog_proof.verify_consistency(m, n, b"\0" * 32, tree, proof)
    with pytest.raises(_tlog.LogError, match="rollback"):
        _tlog_proof.verify_consistency(5, 4, leaves[0], leaves[1], [])


def test_a_receipt_verifies_alone_and_pins_the_log_key(tmp_path):
    root = _log(tmp_path, 5)
    receipt = json.loads(json.dumps(_tlog_receipt.make(root, LOG, 3)))
    assert _tlog_receipt.verify(receipt, vkey=_vkey(root))["size"] == 5
    other = _tlog_note.vkey_for(LOG, Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(_tlog.LogError, match="signature"):
        _tlog_receipt.verify(receipt, vkey=other)
    receipt["entry"] = "ZW50cnkgNA=="  # entry 4 under entry 3's proof
    with pytest.raises(_tlog.LogError, match="inclusion"):
        _tlog_receipt.verify(receipt)


# --- witnesses ----------------------------------------------------------------- #


def _witnesses(n=3):
    keys = [Ed25519PrivateKey.generate() for _ in range(n)]
    names = [f"w{i}.example" for i in range(n)]
    vkeys = [
        _tlog_cosign.witness_vkey(nm, k.public_key().public_bytes_raw())
        for nm, k in zip(names, keys)
    ]
    return keys, names, vkeys


def test_a_split_view_is_detected_with_two_of_three_witnesses(tmp_path):
    honest = _log(tmp_path, 4)
    vkey = _vkey(honest)
    fork = tmp_path / "fork"  # same log key, same size, different history
    fork.mkdir()
    (fork / "key").write_bytes((honest / "key").read_bytes())
    (fork / "vkey").write_bytes((honest / "vkey").read_bytes())
    for i in range(4):
        _tlog_note.append(fork, LOG, lambda _e, i=i: f"forged {i}".encode())
    view_a, view_b = (honest / "checkpoint").read_bytes(), (fork / "checkpoint").read_bytes()
    keys, names, vkeys = _witnesses()
    states = [tmp_path / f"state{i}" for i in range(3)]
    cosigned = view_a
    for key, name, state in zip(keys[:2], names[:2], states[:2]):  # two honest witnesses see A
        cosigned = _witness.witness(cosigned, vkey, key, name, state)["checkpoint"].encode()
    # the third (colluding) witness cosigns B; the honest ones refuse it
    forged = _witness.witness(view_b, vkey, keys[2], names[2], states[2])["checkpoint"].encode()
    for key, name, state in zip(keys[:2], names[:2], states[:2]):
        with pytest.raises(_tlog.LogError, match="fork"):
            _witness.witness(view_b, vkey, key, name, state)
    assert sorted(_tlog_cosign.check_quorum(cosigned, vkeys, 2, 3)) == names[:2]
    with pytest.raises(_tlog.LogError, match="quorum not met"):
        _tlog_cosign.check_quorum(forged, vkeys, 2, 3)


def test_a_witness_advances_only_on_a_consistency_proof_and_refuses_rollback(tmp_path):
    root = _log(tmp_path, 3)
    vkey, (key, *_), (name, *_) = _vkey(root), *_witnesses(1)[:2]
    state = tmp_path / "state"
    old = (root / "checkpoint").read_bytes()
    _witness.witness(old, vkey, key, name, state)
    for i in range(3, 300):
        _tlog_note.append(root, LOG, lambda _e, i=i: f"entry {i}".encode())
    new = (root / "checkpoint").read_bytes()
    with pytest.raises(_tlog.LogError, match="consistency proof"):
        _witness.witness(new, vkey, key, name, state)
    result = _witness.witness(new, vkey, key, name, state, tiles=root)
    assert (result["previous_size"], result["size"]) == (3, 300)
    with pytest.raises(_tlog.LogError, match="rollback"):
        _witness.witness(old, vkey, key, name, state)


def test_a_cosignature_is_not_a_log_signature_and_vkeys_are_checked():
    keys, names, vkeys = _witnesses(1)
    log_vkey = _tlog_note.vkey_for(names[0], keys[0].public_key().public_bytes_raw())
    with pytest.raises(_tlog.LogError):
        _tlog_cosign.parse_witness_vkey(log_vkey)  # type 0x01 is not 0x04
    with pytest.raises(ValueError):
        _tlog_cosign.parse_quorum("3-of-2")
    assert _tlog_cosign.parse_quorum("2-of-3") == (2, 3)


# --- remote audit log: push receipts, fetch consistency ------------------------ #


def test_push_gets_a_receipt_and_fetch_refuses_a_rollback(tmp_path, monkeypatch):
    service, _, _ = _remote(tmp_path, monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    origin.put_run(_run("a"), ref="heads/main")
    pushed = repository_client.push(origin, URL, ref="heads/main")
    assert pushed.transparency["status"] == "included"
    receipts = _remote_tlog.stored_receipts(origin.path)
    assert len(receipts) == 1 and _tlog_receipt.verify(receipts[0])["ok"]
    clone = Repo.init(tmp_path / "clone")
    first = repository_client.fetch(clone, URL)
    assert first.transparency["status"] == "pinned"
    again = repository_client.fetch(clone, URL)
    assert again.transparency["status"] == "consistent"
    log = Path(str(service.audit.path) + ".tlog")
    saved = (log / "checkpoint").read_bytes()
    repository_client.fetch(clone, URL)  # the log grows on every request
    (log / "checkpoint").write_bytes(saved)  # the server rolls its log back
    with pytest.raises(_tlog.LogError, match="rollback|fork"):
        repository_client.fetch(clone, URL)


def test_a_server_without_a_log_is_reported_unavailable(tmp_path, monkeypatch):
    service, _, _ = _remote(tmp_path, monkeypatch)
    monkeypatch.setattr("opentine.remote._audit_tlog.tlog_root", lambda _audit: None)
    origin = Repo.init(tmp_path / "origin")
    origin.put_run(_run("a"), ref="heads/main")
    assert repository_client.push(origin, URL, ref="heads/main").transparency == {
        "status": "unavailable"
    }


# --- bundles ------------------------------------------------------------------- #


def _logged_repo(tmp_path: Path) -> Repo:
    repo = Repo.init(tmp_path / "repo")
    with _oplog.operation("test"):
        repo.put_run(_run("b"), ref="heads/main")
    return repo


def test_bundle_receipts_verify_from_the_bundle_alone(tmp_path):
    repo = _logged_repo(tmp_path)
    data = _bundle.create(repo, ["heads/main"], transparency=True)
    plain = _bundle.create(repo, ["heads/main"])
    assert b"transparency" not in plain  # opt-in: older readers keep reading defaults
    checked = _bundle.verify(data)
    vkey = _tlog_note.stored_vkey(_oplog.log_root(repo.path))
    result = _transparency.check(checked.transparency, checked.refs, vkeys=[vkey])
    assert result["covered"] == ["heads/main"] and result["uncovered"] == []
    keys, names, vkeys = _witnesses()
    with pytest.raises(_tlog.LogError, match="quorum"):
        _transparency.check(checked.transparency, checked.refs, witnesses=vkeys, quorum=(2, 3))


def test_verify_offline_witnesses_cli(tmp_path, capsys):
    root = _log(tmp_path, 2)
    keys, names, vkeys = _witnesses()
    note = (root / "checkpoint").read_bytes()
    for key, name in zip(keys[:2], names[:2]):
        note = _witness.witness(note, _vkey(root), key, name, tmp_path / name)[
            "checkpoint"
        ].encode()
    path = tmp_path / "checkpoint"
    path.write_bytes(note)
    argv = ["verify", str(path), "--offline", "--witnesses", "2-of-3", "--log-vkey", _vkey(root)]
    for vkey in vkeys:
        argv += ["--witness-vkey", vkey]
    assert _code(argv + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["cosigned_by"] == names[:2]
    assert _code([*argv[:4], "3-of-3", *argv[5:]]) == 4
    assert _code(["verify", str(path), "--witnesses", "2-of-3"]) == 1  # needs --offline


def _code(argv: list[str]) -> int:
    try:
        cli.main(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_witness_cli_prints_its_vkey_and_cosigns(tmp_path, capsys):
    from opentine._signing_keys import generate_ed25519

    seed, _ = generate_ed25519()
    key = tmp_path / "w.key"
    key.write_text(seed + "\n")
    key.chmod(0o600)
    root = _log(tmp_path, 3)
    (tmp_path / "cp").write_bytes((root / "checkpoint").read_bytes())
    base = ["--key", str(key), "--name", "w.example"]
    assert _code(["witness", "vkey", *base]) == 0
    vkey = capsys.readouterr().out.strip()
    state = ["--state", str(tmp_path / "state")]
    cosign = ["witness", "cosign", str(tmp_path / "cp"), "--log-vkey", _vkey(root), *base, *state]
    assert _code(cosign) == 0
    note = capsys.readouterr().out.encode()
    assert list(_tlog_cosign.cosigners(note, [vkey])) == ["w.example"]
    (tmp_path / "cp").write_bytes(note.replace(b"\n3\n", b"\n2\n", 1))  # a forged rollback
    assert _code(cosign) == 4
