"""0.59: key roles grant powers only from an owner-signed trust bundle.

Before 0.59 ``.tine/key-roles.toml`` was trusted as written, so a loop that can
write the repository could add its own key to ``policy``, ``scorer`` or
``stopper`` and then sign its own promotion policy, evals or stops. Now an
unsigned file is ``roles: unpinned``: it may refuse (key separation) but
grants nothing. Roles count when a trust bundle (SPEC 8.26) carries them and
its owner key is pinned outside the repository; an older serial is refused.
"""

# ruff: noqa: F811 -- fixtures imported from the 0.57/0.58/0.60 suites
from __future__ import annotations

import json
import subprocess

import pytest

from opentine import _key_roles_pin, cli
from opentine._key_roles import KeyRoleError
from opentine.coord import _loop_stop
from opentine.repository import Repo
from tests.key_roles_helpers import (  # noqa: F401
    OWNER_NAME,
    OWNER_VKEY,
    bundle,
    isolated_trust_config,
    pin_owner,
    pin_roles,
)
from tests.lineage_helpers import RECORDER
from tests.promote_helpers import EVALER, RUN_B, fingerprint, write_key
from tests.test_051_trust_bundle import NODE, UI, needs_node
from tests.test_057_loop_durable import _fpr, _key
from tests.test_057_promote_pins import _at, _sign_policy, repo, room  # noqa: F401
from tests.test_058_lineage_trust import _check, loop  # noqa: F401
from tests.test_058_promote import _codes, _good

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
SIGNER = "9e" * 32


def _unsigned(repo: Repo, **roles: list[str]) -> None:
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def test_a_policy_role_in_an_unsigned_file_grants_nothing(room, repo, capsys):
    _unsigned(repo, policy=[fingerprint(SIGNER)])  # the loop names its own key
    signed = _sign_policy(room, capsys, SIGNER, "signed.json")
    args = [*_good(room, capsys), *_at(repo), "--policy-attestation", signed]
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and _codes(row) == {"promote.policy-unsigned"}
    assert "unpinned" in row["refusals"][0]["detail"]
    pin_roles(repo.path)  # the owner signs the same roles: now they count
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 0, row.get("refusals")


def test_an_unsigned_scorer_role_leaves_lineage_signers_unpinned(loop, capsys):
    _, repo, _, forged, _ = loop
    _unsigned(repo, optimizer=[fingerprint(RECORDER)], scorer=[fingerprint(EVALER)])
    code, row = _check(capsys, repo, forged)
    assert row["signers"] == "unpinned"
    pin_roles(repo.path)
    code, row = _check(capsys, repo, forged)
    assert code == 1 and row["signers"] == "pinned"


def test_an_unsigned_stopper_role_does_not_verify_a_stop(tmp_path):
    repo = Repo.init(tmp_path / "r")
    _unsigned(repo, stopper=[_fpr(9)])
    _loop_stop.stop(repo, "opt", _key(9))
    assert "unpinned" in _loop_stop.loop_state(repo, "opt")["verification"]
    pin_roles(repo.path)
    assert _loop_stop.loop_state(repo, "opt")["verification"] == "verified"


def test_keys_lint_reports_where_the_roles_come_from(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    at = ["keys", "lint", "--repo", repo.path.parent.as_posix(), "--json"]
    assert _cli(capsys, *at)[1]["pinning"] == "absent"
    _unsigned(repo, scorer=[fingerprint(EVALER)])
    assert _cli(capsys, *at)[1]["pinning"] == "unpinned"
    pin_roles(repo.path)
    code, row = _cli(capsys, *at)
    assert row["pinning"] == "pinned" and row["roles"]["scorer"] == [fingerprint(EVALER)]


def test_a_bundle_from_another_owner_or_an_older_serial_is_refused(tmp_path):
    repo = Repo.init(tmp_path / "r")
    _unsigned(repo, policy=[fingerprint(SIGNER)])
    pin_roles(repo.path, serial=5)
    assert _key_roles_pin.resolve(repo.path)["status"] == "pinned"
    roles = {"policy": [fingerprint(EVALER)]}
    (repo.path / "trust-bundle.note").write_bytes(bundle(roles, 4))  # rollback
    with pytest.raises(KeyRoleError, match="older than 5"):
        _key_roles_pin.resolve(repo.path)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _trust_bundle

    rogue = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32)
    payload = json.loads((repo.path / "trust-bundle.note").read_bytes().split(b"\n")[1])
    payload["serial"] = 9
    (repo.path / "trust-bundle.note").write_bytes(_trust_bundle.sign(payload, rogue, OWNER_NAME))
    with pytest.raises(KeyRoleError, match="not signed by the pinned owner"):
        _key_roles_pin.resolve(repo.path)


def test_trust_bundle_create_signs_existing_key_roles(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    _unsigned(repo, scorer=[fingerprint(EVALER)], optimizer=[fingerprint(RECORDER)])
    owner = write_key(tmp_path / "owner.key", "42" * 32)
    out = repo.path / "trust-bundle.note"
    code, row = _cli(capsys, "trust", "bundle", "create", "--key", owner.as_posix(), "--name",
                     OWNER_NAME, "--serial", "1", "--pin", fingerprint(EVALER), "--key-roles",
                     (repo.path / "key-roles.toml").as_posix(), "--out", out.as_posix(),
                     "--json")  # fmt: skip
    assert code == 0 and row["key_roles"]["scorer"] == [fingerprint(EVALER)]
    assert row["owner_vkey"] == OWNER_VKEY
    assert _key_roles_pin.resolve(repo.path)["status"] == "unpinned"  # owner not pinned yet
    pin_owner()
    found = _key_roles_pin.resolve(repo.path)
    assert found["status"] == "pinned" and found["roles"]["optimizer"] == [fingerprint(RECORDER)]


ROLES_JS = """
import { readFileSync } from "node:fs";
import { openTrustBundle } from "./tine-verifier.js";
const [note, owner] = process.argv.slice(1);
const bundle = openTrustBundle(new Uint8Array(readFileSync(note)), owner);
console.log(JSON.stringify({ serial: bundle.serial, keyRoles: bundle.keyRoles }));
"""


@needs_node
def test_the_ts_verifier_reads_the_same_signed_key_roles(tmp_path):
    note = tmp_path / "roles.note"
    roles = {"scorer": [fingerprint(EVALER)], "optimizer": [fingerprint(RECORDER)]}
    note.write_bytes(bundle(roles, 3))
    done = subprocess.run([NODE, "--input-type=module", "-e", ROLES_JS, note.as_posix(),
                           OWNER_VKEY], capture_output=True, text=True, timeout=120,
                          cwd=UI)  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"serial": 3, "keyRoles": roles}
