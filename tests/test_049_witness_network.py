"""0.49: the witness-network registry, the hosted-log 2-of-3 policy and ``witness doctor``.

The policy test runs three real ``tine witness serve`` processes on loopback,
the shape a hosted log's required witness set takes; operating the public
witnesses themselves is recorded as outstanding in docs/witness/OPERATING.md.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _schemas, _witness_http, _witness_network, cli
from opentine._signing_keys import ed25519_private_from_file, generate_ed25519
from opentine._witness_ops import Operator
from opentine.repository import _tlog_cosign, _tlog_note
from opentine.repository._tlog import LogError

ROOT = Path(__file__).resolve().parents[1]
LOG = "example.com/log"


def _log(root: Path, n: int, prefix: str = "entry", start: int = 0) -> bytes:
    for i in range(start, n):
        _tlog_note.append(root, LOG, lambda _e, i=i: f"{prefix} {i}".encode())
    return (root / "checkpoint").read_bytes()


def _code(argv: list[str]) -> int:
    try:
        cli.main(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _key(path: Path) -> str:
    seed, _ = generate_ed25519()
    path.write_text(seed + "\n")
    path.chmod(0o600)
    return path.as_posix()


def _vkey(name: str, key: Ed25519PrivateKey) -> str:
    return _tlog_cosign.witness_vkey(name, key.public_key().public_bytes_raw())


def _registry(log_vkey: str, witnesses: list[tuple[str, str, list[str]]], quorum="2-of-3"):
    return {"schema": "opentine-witness-network/1", "log": {"origin": LOG, "vkey": log_vkey},
            "policy": {"quorum": quorum}, "witnesses": [
                {"name": n, "operator": f"Operator {n}", "url": u, "vkeys": v}
                for n, u, v in witnesses]}  # fmt: skip


@pytest.fixture
def network(tmp_path):
    root = tmp_path / "log"
    note = _log(root, 3)
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    names = [f"w{i}.example" for i in range(3)]
    entries = [(n, f"https://{n}", [_vkey(n, k)]) for n, k in zip(names, keys, strict=True)]
    return note, keys, names, _registry(_tlog_note.stored_vkey(root), entries)


def test_a_registry_that_meets_the_policy_validates_and_against_its_schema(network):
    *_, doc = network
    assert _witness_network.validate(doc) is doc
    assert _schemas.validate(doc) == ("opentine-witness-network-1", [])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["witnesses"].pop(),  # two witnesses cannot be 2-of-3
        lambda d: d["policy"].update(quorum="1-of-3"),  # not a majority
        lambda d: (
            d["witnesses"].append(copy.deepcopy(d["witnesses"][0])),
            d["policy"].update(quorum="2-of-4"),
        ),  # fmt: skip
        lambda d: d["witnesses"][1].update(operator=d["witnesses"][0]["operator"].upper()),
        lambda d: d["witnesses"][1].update(url="http://w1.example"),
        lambda d: d["witnesses"][1].update(vkeys=d["witnesses"][0]["vkeys"]),
        lambda d: d["log"].update(origin="other.example/log"),
        lambda d: d.update(schema="opentine-witness-network/2"),
        lambda d: d["witnesses"][0].update(extra="x"),
    ],
)
def test_a_registry_short_of_the_policy_is_refused(network, mutate):
    *_, doc = network
    mutate(doc)
    with pytest.raises(LogError):
        _witness_network.validate(doc)


def test_any_listed_key_counts_once_per_witness(network):
    note, keys, names, doc = network
    nxt = Ed25519PrivateKey.generate()
    doc["witnesses"][0]["vkeys"].append(_vkey(names[0], nxt))
    _witness_network.validate(doc)
    both = _tlog_cosign.cosign(_tlog_cosign.cosign(note, keys[0], names[0]), nxt, names[0])
    with pytest.raises(LogError, match="1 of 2-of-3"):
        _witness_network.check(both, doc)  # one witness with two keys is still one
    assert sorted(_witness_network.check(_tlog_cosign.cosign(both, keys[2], names[2]), doc)) == [
        names[0], names[2]]  # fmt: skip


def _serve(tmp_path: Path, name: str, log_vkey: str) -> tuple[subprocess.Popen, str, str]:
    key = _key(tmp_path / f"{name}.key")
    state = (tmp_path / f"{name}.state").as_posix()
    argv = [sys.executable, "-c", "from opentine.cli import main; main()", "witness", "serve"]
    argv += ["--key", key, "--name", name, "--log-vkey", log_vkey, "--state", state]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
    line = process.stdout.readline().strip()
    assert line.startswith("listening on "), line
    public = ed25519_private_from_file(key, legacy_warn=False).public_key().public_bytes_raw()
    return process, line.split(" ", 2)[2], _tlog_cosign.witness_vkey(name, public)


def _submit(tmp_path: Path, tiles: Path, urls: list[str], tag: str) -> tuple[int, Path]:
    cp, out = tmp_path / f"cp-{tag}", tmp_path / f"cosigned-{tag}"
    cp.write_bytes((tiles / "checkpoint").read_bytes())
    argv = ["witness", "submit", str(cp), "--tiles", str(tiles), "--out", str(out)]
    return _code([*argv, *(a for u in urls for a in ("--url", u))]), out


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_the_hosted_log_requires_two_of_three_witness_processes(tmp_path, capsys):
    honest = tmp_path / "log"
    _log(honest, 3)
    log_vkey = _tlog_note.stored_vkey(honest)
    servers = [_serve(tmp_path, f"w{i}.example", log_vkey) for i in range(3)]
    try:
        urls = [url for _, url, _ in servers]
        doc = _registry(log_vkey, [(f"w{i}.example", u, [v]) for i, (_, u, v) in
                                   enumerate(servers)])  # fmt: skip
        registry = tmp_path / "network.json"
        registry.write_text(json.dumps(doc), encoding="utf-8")
        verify = ["verify", "", "--offline", "--witnesses", str(registry), "--json"]
        assert _submit(tmp_path, honest, urls, "all")[0] == 0
        verify[1] = str(tmp_path / "cosigned-all")
        capsys.readouterr()
        assert _code(verify) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["cosigned_by"] == ["w0.example", "w1.example", "w2.example"]
        assert result["registry"] == {"log": LOG, "quorum": "2-of-3"}
        # one witness is down: the other two still meet the policy (and a 409 round trip)
        _log(honest, 40, start=3)
        assert _submit(tmp_path, honest, urls[:2], "two")[0] == 0
        verify[1] = str(tmp_path / "cosigned-two")
        assert _code(verify) == 0
        # only one witness reachable: fails closed
        _log(honest, 50, start=40)
        assert _submit(tmp_path, honest, urls[2:], "one")[0] == 0
        verify[1] = str(tmp_path / "cosigned-one")
        assert _code(verify) == 4
        # a split view: the honest witnesses refuse it, one colluding cosignature is not enough
        fork = tmp_path / "fork"
        fork.mkdir()
        for name in ("key", "vkey"):
            (fork / name).write_bytes((honest / name).read_bytes())
        forged = _log(fork, 50, prefix="forged")
        assert _submit(tmp_path, fork, urls, "forged")[0] == 4
        colluder = Ed25519PrivateKey.generate()
        doc["witnesses"][2]["vkeys"] = [_vkey("w2.example", colluder)]
        registry.write_text(json.dumps(doc), encoding="utf-8")
        (tmp_path / "bad").write_bytes(_tlog_cosign.cosign(forged, colluder, "w2.example"))
        verify[1] = str(tmp_path / "bad")
        assert _code(verify) == 4
    finally:
        for process, *_ in servers:
            process.terminate()
            process.wait(timeout=30)
            process.stdout.close()


def test_registry_mode_refuses_extra_key_flags_and_a_bad_registry(tmp_path, network):
    note, *_, doc = network
    (tmp_path / "cp").write_bytes(note)
    (tmp_path / "network.json").write_text(json.dumps(doc), encoding="utf-8")
    base = ["verify", str(tmp_path / "cp"), "--offline", "--witnesses"]
    assert _code([*base, str(tmp_path / "network.json"), "--witness-vkey", "x"]) == 2
    doc["policy"]["quorum"] = "1-of-3"
    (tmp_path / "weak.json").write_text(json.dumps(doc), encoding="utf-8")
    assert _code([*base, str(tmp_path / "weak.json")]) == 4
    assert _code([*base, str(tmp_path / "missing.json")]) == 4


class _Running:
    def __init__(self, keys, name, logs, state):
        operator = Operator(keys, name, logs, state, rate_limit=0)
        self.server = _witness_http.make_server(("127.0.0.1", 0), logs, keys, name, state,
                                                operator=operator)  # fmt: skip
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_witness_doctor_passes_a_good_deployment_and_names_each_failure(tmp_path, capsys):
    root = tmp_path / "log"
    _log(root, 3)
    log_vkey = _tlog_note.stored_vkey(root)
    path = _key(tmp_path / "w0.key")
    key = ed25519_private_from_file(path, legacy_warn=False)
    name, state = "w0.example", tmp_path / "state"
    with _Running([key], name, {LOG: log_vkey}, state) as running:
        others = [
            (
                f"w{i}.example",
                f"https://w{i}.example",
                [_vkey(f"w{i}.example", Ed25519PrivateKey.generate())],
            )
            for i in (1, 2)
        ]
        doc = _registry(log_vkey, [(name, running.url, [_vkey(name, key)]), *others])
        (tmp_path / "network.json").write_text(json.dumps(doc), encoding="utf-8")
        argv = ["witness", "doctor", "--key", path, "--name", name, "--log-vkey", log_vkey,
                "--state", str(state), "--registry", str(tmp_path / "network.json"),
                "--url", running.url, "--json"]  # fmt: skip
        capsys.readouterr()
        assert _code(argv) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["ok"] and _schemas.validate_output(result) == []
        assert [c["check"] for c in result["checks"]] == [
            "keys",
            "key-files",
            "state",
            "logs",
            "registry",
            "health",
            "keys-served",
            "url",
        ]
        assert path not in json.dumps(result)  # never names a key path
        # the served keys and the registry disagree with another name's key
        argv[argv.index("--name") + 1] = "w9.example"
        assert _code(argv) == 4
        failed = {c["check"] for c in json.loads(capsys.readouterr().out)["checks"] if not c["ok"]}
        assert {"registry", "keys-served"} <= failed
    if os.name != "nt":
        Path(path).chmod(0o644)
        assert _code(["witness", "doctor", "--key", path, "--name", name, "--log-vkey", log_vkey,
                      "--state", str(state), "--json"]) == 4  # fmt: skip
        checks = json.loads(capsys.readouterr().out)["checks"]
        assert [c["ok"] for c in checks if c["check"] == "key-files"] == [False]


def test_the_deploy_kit_pins_its_base_image_and_holds_no_secret():
    kit = ROOT / "deploy" / "witness"
    lines = (kit / "Containerfile").read_text("utf-8").splitlines()
    bases = [line.split()[1] for line in lines if line.startswith("FROM ")]
    assert bases and all(not b.endswith(":latest") for b in bases)
    assert all(any(c.isdigit() for c in b.rsplit(":", 1)[-1]) for b in bases)  # exact version
    for path in kit.iterdir():
        text = path.read_text("utf-8")
        assert "PRIVATE KEY" not in text and "AWS_SECRET" not in text, path.name
    assert "/run/secrets/witness-" in (kit / "entrypoint.sh").read_text("utf-8")
    for doc in ("OPERATING.md", "NETWORK.md", "RECRUITING.md"):
        assert "outstanding" in (ROOT / "docs" / "witness" / doc).read_text("utf-8").lower()


def test_the_published_example_registry_meets_the_policy():
    doc = json.loads((ROOT / "deploy/witness/network.example.json").read_text("utf-8"))
    assert _witness_network.validate(doc) is doc
    assert _schemas.validate(doc) == ("opentine-witness-network-1", [])
