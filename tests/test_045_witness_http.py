"""0.45: the C2SP tlog-witness HTTP protocol (``tine witness serve|submit``)."""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _witness_http, cli
from opentine._signing_keys import ed25519_private_from_file, generate_ed25519
from opentine.repository import _tlog_cosign, _tlog_note

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


def test_request_bodies_parse_and_reject_malformed_input():
    proof = [b"\1" * 32, b"\2" * 32]
    assert _witness_http.parse_request(_witness_http.encode_request(5, proof, b"cp\n")) == (
        5, proof, b"cp\n")  # fmt: skip
    for bad in (b"old 01\n\ncp", b"old x\n\ncp", b"new 1\n\ncp", b"old 1\nAAAA\n\ncp", b"old 1"):
        with pytest.raises(_witness_http.WitnessHTTPError) as caught:
            _witness_http.parse_request(bad)
        assert caught.value.status == 400


def test_the_endpoint_answers_404_403_409_and_422(tmp_path):
    root = tmp_path / "log"
    note = _log(root, 3)
    logs = {LOG: _tlog_note.stored_vkey(root)}
    key, state = Ed25519PrivateKey.generate(), tmp_path / "state"

    def status(body: bytes) -> int:
        try:
            _witness_http.add_checkpoint(body, logs, key, "w.example", state)
        except _witness_http.WitnessHTTPError as exc:
            return exc.status
        return 200

    assert status(_witness_http.encode_request(0, [], b"other/log\n1\nAA==\n\n")) == 404
    assert status(_witness_http.encode_request(0, [], note.replace(b"\n3\n", b"\n4\n"))) == 403
    assert status(_witness_http.encode_request(0, [], note)) == 200
    newer = _log(root, 5, start=3)
    assert status(_witness_http.encode_request(0, [], newer)) == 409
    assert status(_witness_http.encode_request(3, [b"\0" * 32], newer)) == 422


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


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_two_witness_processes_cosign_over_http_and_a_split_view_fails_closed(tmp_path, capsys):
    honest = tmp_path / "log"
    _log(honest, 3)
    vkey = _tlog_note.stored_vkey(honest)
    servers = [_serve(tmp_path, f"w{i}.example", vkey) for i in range(2)]
    try:
        urls = [url for _, url, _ in servers]
        colluder = Ed25519PrivateKey.generate()
        vkeys = [v for *_, v in servers]
        vkeys.append(
            _tlog_cosign.witness_vkey("w2.example", colluder.public_key().public_bytes_raw())
        )
        # first contact (old 0), then a 409 round trip with a proof from the tiles
        for size in (3, 300):
            _log(honest, size, start=3)
            cp = tmp_path / f"cp{size}"
            cp.write_bytes((honest / "checkpoint").read_bytes())
            out = tmp_path / f"cosigned{size}"
            argv = ["witness", "submit", str(cp), "--tiles", str(honest), "--out", str(out)]
            assert _code([*argv, *(a for u in urls for a in ("--url", u))]) == 0
        verify = ["verify", str(out), "--offline", "--witnesses", "2-of-3", "--log-vkey", vkey]
        verify += [a for v in vkeys for a in ("--witness-vkey", v)]
        assert _code(verify) == 0
        # a split view: same log key, same size, another history
        fork = tmp_path / "fork"
        fork.mkdir()
        for name in ("key", "vkey"):
            (fork / name).write_bytes((honest / name).read_bytes())
        forged = _log(fork, 300, prefix="forged")
        (tmp_path / "forged").write_bytes(forged)
        capsys.readouterr()
        argv = ["witness", "submit", str(tmp_path / "forged"), "--tiles", str(fork)]
        assert _code([*argv, *(a for u in urls for a in ("--url", u))]) == 4
        assert "422" in capsys.readouterr().err
        bad = _tlog_cosign.cosign(forged, colluder, "w2.example")
        (tmp_path / "bad").write_bytes(bad)
        verify[1] = str(tmp_path / "bad")
        assert _code(verify) == 4
    finally:
        for process, *_ in servers:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()


def test_an_in_process_server_round_trips(tmp_path):
    root = tmp_path / "log"
    note = _log(root, 2)
    key = Ed25519PrivateKey.generate()
    logs = {LOG: _tlog_note.stored_vkey(root)}
    server = _witness_http.make_server(("127.0.0.1", 0), logs, key, "w", tmp_path / "s")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        lines = _witness_http.submit(url, note, proof_for=lambda _old: [])
        vkey = _tlog_cosign.witness_vkey("w", key.public_key().public_bytes_raw())
        assert list(_tlog_cosign.cosigners(note + lines, [vkey])) == ["w"]
        with pytest.raises(_witness_http.WitnessHTTPError):
            _witness_http.submit(url + "/nope", note, proof_for=lambda _old: [])
    finally:
        server.shutdown()
        server.server_close()
