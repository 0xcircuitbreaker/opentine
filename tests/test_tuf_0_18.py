"""0.18 trust hardening: the minimal TUF client behind ``tine trust root update``.

No network: ``_tuf_fetch.FETCH`` serves a dict of fixture metadata that this
module generates and signs in-test (ed25519 and ecdsa-sha2-nistp256 keys).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from opentine import _tuf_fetch, cli
from opentine._tuf_client import update
from opentine._tuf_meta import TUFError, canonical
from tests._sigstore_fakes import FakeLog
from tests.test_fulcio_sct_0_18 import SctFulcio
from tests.test_trusted_root_0_18 import make_root

URL = "https://tuf.test"
NOW = dt.datetime.now(dt.UTC)


def _exp(days: int) -> str:
    return (NOW + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Key:
    def __init__(self, kind: str = "ed25519") -> None:
        self.kind = kind
        if kind == "ed25519":
            self.priv = ed25519.Ed25519PrivateKey.generate()
            raw = self.priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            self.obj = {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": raw.hex()}}
        else:
            self.priv = ec.generate_private_key(ec.SECP256R1())
            pem = self.priv.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.obj = {"keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256",
                        "keyval": {"public": pem.decode()}}  # fmt: skip
        self.id = hashlib.sha256(canonical(self.obj)).hexdigest()

    def sign(self, data: bytes) -> str:
        if self.kind == "ed25519":
            return self.priv.sign(data).hex()
        return self.priv.sign(data, ec.ECDSA(hashes.SHA256())).hex()


def _signed(signed: dict, keys: list[Key]) -> bytes:
    data = canonical(signed)
    sigs = [{"keyid": k.id, "sig": k.sign(data)} for k in keys]
    return json.dumps({"signed": signed, "signatures": sigs}).encode()


class Repo:
    def __init__(self, kind: str = "ed25519") -> None:
        self.roles = {r: [Key(kind)] for r in ("root", "timestamp", "snapshot", "targets")}
        self.threshold = {r: 1 for r in self.roles}
        self.files: dict[str, bytes] = {}
        self.versions = {"root": 1, "timestamp": 1, "snapshot": 1, "targets": 1}
        self.expires = {r: 30 for r in self.roles}
        log, fulcio = FakeLog(), SctFulcio()
        self.payload = json.dumps(make_root(log, fulcio)).encode()
        self.root_bytes = self.make_root(self.roles["root"])
        self.files[f"{URL}/1.root.json"] = self.root_bytes

    def root_signed(self) -> dict:
        keys = {k.id: k.obj for ks in self.roles.values() for k in ks}
        roles = {r: {"keyids": [k.id for k in ks], "threshold": self.threshold[r]}
                 for r, ks in self.roles.items()}  # fmt: skip
        return {"_type": "root", "spec_version": "1.0.31", "version": self.versions["root"],
                "expires": _exp(self.expires["root"]), "keys": keys, "roles": roles,
                "consistent_snapshot": True}  # fmt: skip

    def make_root(self, signers: list[Key]) -> bytes:
        return _signed(self.root_signed(), signers)

    def rotate_root(self, new_keys: list[Key], signers: list[Key] | None = None) -> None:
        old = self.roles["root"]
        self.roles["root"] = new_keys
        self.versions["root"] += 1
        v = self.versions["root"]
        self.files[f"{URL}/{v}.root.json"] = self.make_root(
            signers if signers is not None else old + new_keys
        )

    def publish(self, *, target: bytes | None = None, target_info: dict | None = None) -> None:
        v = self.versions
        target = self.payload if target is None else target
        digest = hashlib.sha256(target).hexdigest()
        info = target_info or {"length": len(target), "hashes": {"sha256": digest}}
        sha = info["hashes"].get("sha256", "x")
        self.files[f"{URL}/targets/{sha}.trusted_root.json"] = target
        targets = _signed({"_type": "targets", "spec_version": "1.0", "version": v["targets"],
                           "expires": _exp(self.expires["targets"]),
                           "targets": {"trusted_root.json": info}},
                          self.roles["targets"])  # fmt: skip
        self.files[f"{URL}/{v['targets']}.targets.json"] = targets
        snapshot = _signed({"_type": "snapshot", "spec_version": "1.0", "version": v["snapshot"],
                            "expires": _exp(self.expires["snapshot"]),
                            "meta": {"targets.json": {"version": v["targets"]}}},
                           self.roles["snapshot"])  # fmt: skip
        self.files[f"{URL}/{v['snapshot']}.snapshot.json"] = snapshot
        meta = {"version": v["snapshot"], "length": len(snapshot),
                "hashes": {"sha256": hashlib.sha256(snapshot).hexdigest()}}  # fmt: skip
        self.files[f"{URL}/timestamp.json"] = _signed(
            {"_type": "timestamp", "spec_version": "1.0", "version": v["timestamp"],
             "expires": _exp(self.expires["timestamp"]), "meta": {"snapshot.json": meta}},
            self.roles["timestamp"],
        )  # fmt: skip


@pytest.fixture
def repo(monkeypatch, tmp_path: Path) -> Repo:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    r = Repo()
    r.publish()
    monkeypatch.setattr(_tuf_fetch, "FETCH", lambda url, limit: r.files.get(url))
    return r


def _base(tmp_path: Path) -> Path:
    return tmp_path / "cfg/opentine/sigstore"


def _first(repo: Repo, tmp_path: Path) -> dict:
    return update(_base(tmp_path), repo_url=URL, initial_root=repo.root_bytes)


def test_canonical_form() -> None:
    assert (
        canonical({"b": [1, True, None], "a": 'q"\\\n'}) == b'{"a":"q\\"\\\\\n","b":[1,true,null]}'
    )
    with pytest.raises(TUFError):
        canonical({"a": 1.5})


def test_happy_path_installs_trusted_root(repo, tmp_path) -> None:
    summary = _first(repo, tmp_path)
    assert (_base(tmp_path) / "trusted_root.json").read_bytes() == repo.payload
    assert summary["root"] == 1 and (_base(tmp_path) / "tuf/state.json").is_file()
    repo.versions["timestamp"] += 1
    repo.publish()
    assert update(_base(tmp_path))["timestamp"] == 2  # stored root + repo url reused


def test_ecdsa_keys(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    r = Repo("ecdsa")
    r.publish()
    monkeypatch.setattr(_tuf_fetch, "FETCH", lambda url, limit: r.files.get(url))
    assert _first(r, tmp_path)["targets"] == 1


def test_first_use_needs_root_and_root_only_once(repo, tmp_path) -> None:
    with pytest.raises(TUFError, match="--root"):
        update(_base(tmp_path), repo_url=URL)
    _first(repo, tmp_path)
    with pytest.raises(TUFError, match="already initialised"):
        _first(repo, tmp_path)


def test_root_rotation_needs_old_and_new_signatures(repo, tmp_path) -> None:
    _first(repo, tmp_path)
    new = [Key()]
    repo.rotate_root(new)
    repo.publish()
    assert update(_base(tmp_path))["root"] == 2


@pytest.mark.parametrize("who", ["new-only", "old-only"])
def test_root_rotation_threshold_failures(repo, tmp_path, who) -> None:
    old, new = repo.roles["root"], [Key()]
    repo.rotate_root(new, signers=new if who == "new-only" else old)
    repo.publish()
    with pytest.raises(TUFError, match="signatures"):
        _first(repo, tmp_path)


def test_threshold_counts_distinct_keys(repo, tmp_path) -> None:
    repo.threshold["timestamp"] = 2
    repo.root_bytes = repo.make_root(repo.roles["root"])
    key = repo.roles["timestamp"][0]
    repo.roles["timestamp"] = [key, key]  # one key signing twice
    repo.publish()
    with pytest.raises(TUFError, match="1 of 2"):
        _first(repo, tmp_path)


def test_wrong_root_version(repo, tmp_path) -> None:
    repo.versions["root"] = 5
    repo.files[f"{URL}/2.root.json"] = repo.make_root(repo.roles["root"])
    with pytest.raises(TUFError, match="carries version 5"):
        _first(repo, tmp_path)


@pytest.mark.parametrize("role", ["root", "timestamp", "snapshot", "targets"])
def test_expired_metadata(repo, tmp_path, role) -> None:
    repo.expires[role] = -1
    repo.root_bytes = repo.make_root(repo.roles["root"])
    repo.publish()
    with pytest.raises(TUFError, match="expired"):
        _first(repo, tmp_path)


def test_timestamp_rollback(repo, tmp_path) -> None:
    repo.versions["timestamp"] = 3
    repo.publish()
    _first(repo, tmp_path)
    repo.versions["timestamp"] = 2
    repo.publish()
    with pytest.raises(TUFError, match="timestamp version rolled back"):
        update(_base(tmp_path))


def test_snapshot_rollback(repo, tmp_path) -> None:
    repo.versions.update(snapshot=3, targets=3)
    repo.publish()
    _first(repo, tmp_path)
    repo.versions.update(timestamp=2, snapshot=4, targets=2)
    repo.publish()
    with pytest.raises(TUFError, match="targets.json version rolled back"):
        update(_base(tmp_path))
    repo.versions.update(timestamp=3, snapshot=2, targets=3)
    repo.publish()
    with pytest.raises(TUFError, match="snapshot version rolled back"):
        update(_base(tmp_path))


def test_rotated_timestamp_key_resets_rollback_state(repo, tmp_path) -> None:
    repo.versions["timestamp"] = 9
    repo.publish()
    _first(repo, tmp_path)
    repo.roles["timestamp"] = [Key()]
    repo.rotate_root(repo.roles["root"])
    repo.versions["timestamp"] = 1
    repo.publish()
    assert update(_base(tmp_path))["timestamp"] == 1


def test_target_hash_and_length_mismatch(repo, tmp_path) -> None:
    good = hashlib.sha256(repo.payload).hexdigest()
    repo.publish(target_info={"length": len(repo.payload), "hashes": {"sha256": good}})
    repo.files[f"{URL}/targets/{good}.trusted_root.json"] = repo.payload[:-1] + b" "
    with pytest.raises(TUFError, match="sha256 does not match"):
        _first(repo, tmp_path)
    repo.publish(target_info={"length": len(repo.payload) + 1, "hashes": {"sha256": good}})
    with pytest.raises(TUFError, match="length does not match"):
        _first(repo, tmp_path)


def test_snapshot_hash_mismatch(repo, tmp_path) -> None:
    name = f"{URL}/1.snapshot.json"
    original = repo.files[name]
    repo.files[name] = original.replace(b'"version": 1', b'"version": 2')  # same length
    with pytest.raises(TUFError, match="snapshot.json sha256 does not match"):
        _first(repo, tmp_path)
    repo.files[name] = original + b" "  # longer than listed: refused before parsing
    with pytest.raises(_tuf_fetch.FetchError, match="exceeds"):
        _first(repo, tmp_path)


def test_invalid_trusted_root_target_is_not_installed(repo, tmp_path) -> None:
    repo.publish(target=b'{"mediaType": "nope"}')
    with pytest.raises(TUFError, match="invalid"):
        _first(repo, tmp_path)
    assert not (_base(tmp_path) / "trusted_root.json").exists()


def test_oversized_response_refused(monkeypatch, repo, tmp_path) -> None:
    monkeypatch.setattr(_tuf_fetch, "FETCH", lambda url, limit: b"x" * (limit + 1))
    with pytest.raises(_tuf_fetch.FetchError, match="exceeds"):
        _first(repo, tmp_path)


def test_cli_update(repo, tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "root.json").write_bytes(repo.root_bytes)
    with pytest.raises(SystemExit) as exc:
        cli.main(["trust", "root", "update", "--repo-url", URL])
    assert exc.value.code == 1 and "--root" in capsys.readouterr().out
    cli.main(["trust", "root", "update", "--repo-url", URL, "--root", "root.json", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "trust root update" and payload["root"] == 1


def test_an_unroutable_address_falls_through_to_the_next_ipv4_first(monkeypatch):
    import socket

    from opentine import _tuf_fetch

    tried = []

    class Sock:
        def __init__(self, family, kind, proto):
            self.family = family

        def settimeout(self, value):
            assert value <= _tuf_fetch.TIMEOUT_SECONDS

        def connect(self, address):
            tried.append(address[0])
            if address[0] != "10.0.0.2":
                raise TimeoutError("unroutable")

        def close(self):
            pass

    infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 443)),
    ]
    monkeypatch.setattr(_tuf_fetch.socket, "getaddrinfo", lambda *a, **k: list(infos))
    monkeypatch.setattr(_tuf_fetch.socket, "socket", Sock)
    assert _tuf_fetch._dial("example.test", 443, 30.0).family == socket.AF_INET
    assert tried == ["10.0.0.1", "10.0.0.2"]
