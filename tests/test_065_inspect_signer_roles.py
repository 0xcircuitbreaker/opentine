"""0.65: ``tine inspect import|verify`` honour owner-pinned key roles.

An optimizer key may not sign Inspect scores; a log signed by it is refused by
``import --require-signed`` and reported ``refused`` by ``verify``. A pinned
scorer key passes; any other key is ``unpinned`` (advisory unless --strict).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine._signing_pins import key_fingerprint
from opentine.cli import main
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "inspect" / "gsm8k.json"
SIGNED_AT = "2026-11-01T12:00:00Z"
HEX = {"optimizer": "21" * 32, "scorer": "22" * 32, "other": "23" * 32}


def _fpr(name: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(HEX[name]))
    return key_fingerprint(key.public_key().public_bytes_raw())


def _tine(capsys, *argv: str) -> tuple[int, str]:
    try:
        main(list(argv))
        code = 0
    except SystemExit as exc:
        code = exc.code or 0
    return code, capsys.readouterr().out


@pytest.fixture
def world(tmp_path):
    repo = Repo.init(tmp_path / "r")
    store = Path(repo.path)
    roles = f'version = 1\n[roles]\noptimizer = ["{_fpr("optimizer")}"]\n' \
            f'scorer = ["{_fpr("scorer")}"]\n'  # fmt: skip
    (store / "key-roles.toml").write_bytes(roles.encode("utf-8"))
    pin_roles(store)
    for name, value in HEX.items():
        (tmp_path / f"{name}.key").write_bytes(value.encode("ascii"))
    log = tmp_path / "gsm8k.json"
    log.write_bytes(FIXTURE.read_bytes())
    return tmp_path, log


def _p(path: Path) -> str:
    return path.as_posix()


def _sign(capsys, root: Path, log: Path, who: str) -> None:
    code, out = _tine(capsys, "inspect", "sign", _p(log), "--key", _p(root / f"{who}.key"),
                      "--signed-at", SIGNED_AT)  # fmt: skip
    assert code == 0, out


def _import(capsys, root: Path, log: Path, *extra: str) -> tuple[int, str]:
    return _tine(capsys, "inspect", "import", _p(log), "--repo", _p(root / "r"),
                 "--created-at", SIGNED_AT, "--json", *extra)  # fmt: skip


def test_the_optimizer_key_is_refused_at_import(world, capsys):
    root, log = world
    code, out = _import(capsys, root, log, "--key", _p(root / "optimizer.key"),
                        "--evals", _p(root / "ev"))  # fmt: skip
    assert code != 0
    assert "key-separation" in out
    assert not (root / "ev").exists()


def test_a_forged_log_signed_by_the_optimizer_is_refused(world, capsys):
    root, log = world
    _sign(capsys, root, log, "optimizer")
    code, out = _import(capsys, root, log, "--require-signed")
    assert code != 0 and "key-separation" in out
    code, out = _tine(capsys, "inspect", "verify", _p(log), "--repo", _p(root / "r"), "--json")
    body = json.loads(out)
    assert code != 0
    assert body["signer"] == _fpr("optimizer") and body["signer_status"] == "refused"
    code, out = _tine(capsys, "inspect", "verify", _p(log), "--repo", _p(root / "r"))
    assert code != 0 and "refused" in out and "ok" != out.strip()


def test_a_pinned_scorer_key_passes(world, capsys):
    root, log = world
    _sign(capsys, root, log, "scorer")
    code, out = _import(capsys, root, log, "--require-signed", "--key",
                        _p(root / "scorer.key"), "--evals", _p(root / "ev"))  # fmt: skip
    assert code == 0, out
    body = json.loads(out)
    assert body["verdicts"]["signer_status"] == "pinned"
    assert body["verdicts"]["signer"] == _fpr("scorer")
    code, out = _tine(capsys, "inspect", "verify", _p(log), "--repo", _p(root / "r"),
                      "--strict", "--json")  # fmt: skip
    body = json.loads(out)
    assert code == 0 and body["ok"] and body["signer_status"] == "pinned"


def test_an_unpinned_key_is_reported_unpinned(world, capsys):
    root, log = world
    code, out = _import(capsys, root, log, "--key", _p(root / "other.key"),
                        "--evals", _p(root / "ev"))  # fmt: skip
    assert code == 0, out
    assert json.loads(out)["verdicts"]["signer_status"] == "unpinned"
    _sign(capsys, root, log, "other")
    code, out = _tine(capsys, "inspect", "verify", _p(log), "--repo", _p(root / "r"))
    assert code == 0 and "signature valid, signer unpinned" in out
    assert out.strip() != "ok"
    code, out = _tine(capsys, "inspect", "verify", _p(log), "--repo", _p(root / "r"),
                      "--json", "--strict")  # fmt: skip
    assert code != 0 and json.loads(out)["signer_status"] == "unpinned"


def test_require_signed_refuses_an_unpinned_signer(world, capsys):
    root, log = world
    _sign(capsys, root, log, "other")
    code, out = _import(capsys, root, log, "--require-signed")
    assert code != 0 and "require-signed" in out
