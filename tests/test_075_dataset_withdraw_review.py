"""0.75 review: withdrawal authority and the untrusted JSON a dataset command reads.

* a later licence annotation by another key cancelled a valid withdrawal;
* a key that annotated an unannotated run first became its contributor;
* a deeply nested tombstones manifest or ``verify-version --file`` claim raised
  ``RecursionError`` instead of the documented refusal, and either file was
  read whole however large it was.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _dataset_version as dv
from opentine import _dataset_withdraw as wd
from tests.dataset_contrib_helpers import annotate
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.test_075_dataset_curate import (  # noqa: F401
    AT,
    CURATOR,
    OPTIMIZER,
    STRANGER,
    _cli,
    _hex,
    _run,
    repo_fixture,
)
from tests.test_075_dataset_withdraw_auth import CONTRIBUTOR, _raw

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SECOND = Ed25519PrivateKey.from_private_bytes(b"\x77" * 32)
DEEP = b'{"tombstones":' + b"[" * 100000 + b"]" * 100000 + b"}"


def _pin_runners(repo, *runners):
    names = ", ".join(f'"{_hex(k)}"' for k in runners)
    (repo.path / "key-roles.toml").write_bytes(
        (
            f'version = 1\n[roles]\ncurator = ["{_hex(CURATOR)}"]\n'
            f'optimizer = ["{_hex(OPTIMIZER)}"]\nrunner = [{names}]\n'
        ).encode()  # fmt: skip
    )
    pin_roles(repo.path)


@pytest.mark.parametrize("later", [STRANGER, SECOND])
def test_a_later_annotation_does_not_cancel_a_valid_withdrawal(repo, later):
    _pin_runners(repo, CONTRIBUTOR, SECOND)
    run = _run(repo, 1)
    annotate(repo, run, CONTRIBUTOR)
    record = wd.withdraw(repo, run, CONTRIBUTOR, "privacy", AT)
    assert dv.withdrawals(repo) == {run: record}
    annotate(repo, run, later)
    assert dv.withdrawals(repo) == {run: record}
    assert dv.curate(repo, "train", "all", CURATOR, AT)["claim"]["withdrawn"] == [run]


def test_a_stranger_who_annotates_first_is_not_the_contributor(repo):
    _pin_runners(repo, CONTRIBUTOR)
    run = _run(repo, 1)
    annotate(repo, run, STRANGER)
    with pytest.raises(PermissionError):
        wd.withdraw(repo, run, STRANGER, "privacy", AT)
    _raw(repo, run, STRANGER)
    assert dv.withdrawals(repo) == {}


def test_a_deep_tombstones_manifest_is_refused(tmp_path):
    path = tmp_path / "t.json"
    path.write_bytes(DEEP)
    with pytest.raises(ValueError, match="cannot read the tombstones"):
        wd.read_tombstones(path)


def test_an_oversized_tombstones_manifest_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(wd, "MAX_JSON_BYTES", 64)
    path = tmp_path / "t.json"
    path.write_bytes(b'{"format": "' + wd.TOMBSTONES.encode() + b'", "tombstones": []}' + b" " * 64)
    with pytest.raises(ValueError, match="larger than 64 bytes"):
        wd.read_tombstones(path)


def test_a_deep_or_oversized_version_file_is_refused(tmp_path, capsys, monkeypatch):
    path = tmp_path / "v.json"
    path.write_bytes(b"[" * 100000 + b"]" * 100000)
    code, _ = _cli(capsys, "dataset", "verify-version", "--file", str(path), "--json")
    err = capsys.readouterr().err
    assert code != 0 and "recursion" not in err.casefold()
    monkeypatch.setattr(wd, "MAX_JSON_BYTES", 8)
    path.write_bytes(b"{}" + b" " * 16)
    code, _ = _cli(capsys, "dataset", "verify-version", "--file", str(path), "--json")
    assert code != 0
