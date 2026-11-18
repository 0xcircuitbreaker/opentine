"""0.58: ``tine keys lint`` -- the optimizer key must not hold scorer, dataset or verdict keys.

Owner decision D12: ``fail:`` findings (key and policy facts) block;
``advisory:`` findings never block unless ``--strict`` asks.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from opentine import _key_roles, cli
from opentine.repository import Repo

OPT, SCORE, DATA, VERDICT = ("sha256:" + c * 64 for c in "abcd")
RAW = "11" * 32


def _policy(repo: Repo, text: str) -> None:
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))


def _roles(**roles: list[str]) -> str:
    lines = ["version = 1", "[roles]"]
    lines += [f"{role} = {json.dumps(keys)}" for role, keys in roles.items()]
    return "\n".join(lines) + "\n"


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _lint(capsys, repo: Repo, *extra: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(["keys", "lint", "--repo", str(repo.path.parent), "--json", *extra])
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 0
    return code, json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_separated_keys_pass_with_no_findings(repo, capsys):
    _policy(repo, _roles(optimizer=[OPT], scorer=[SCORE], dataset=[DATA], verdict=[VERDICT]))
    code, out = _lint(capsys, repo)
    assert code == 0 and out["ok"] and out["findings"] == [] and out["blocking"] == 0
    assert out["roles"]["optimizer"] == [OPT] and out["roles"]["approver"] == []


@pytest.mark.parametrize("role", ["scorer", "dataset", "verdict", "approver"])
def test_an_optimizer_key_holding_an_evaluation_key_is_refused(repo, capsys, role):
    roles = {"optimizer": [OPT], "scorer": [SCORE], "dataset": [DATA], "verdict": [VERDICT]}
    roles[role] = [*roles.get(role, []), OPT]
    _policy(repo, _roles(**roles))
    code, out = _lint(capsys, repo)
    assert code == 1 and not out["ok"] and out["blocking"] == 1
    (finding,) = out["findings"]
    assert finding["code"] == "fail:key-separation.shared"
    assert finding["role"] == role and finding["key"] == OPT


def test_a_candidate_signing_key_is_checked_too(repo, capsys):
    _policy(repo, _roles(scorer=[SCORE], dataset=[DATA], verdict=[VERDICT]))
    code, out = _lint(capsys, repo)
    assert code == 0 and [f["code"] for f in out["findings"]] == ["advisory:key-roles.no-optimizer"]
    code, out = _lint(capsys, repo, "--optimizer-key", VERDICT)
    assert code == 1 and out["findings"][0]["role"] == "verdict"


def test_a_raw_public_key_is_its_fingerprint(repo, capsys):
    fingerprint = "sha256:" + hashlib.sha256(bytes.fromhex(RAW)).hexdigest()
    assert _key_roles.normalize_key(RAW) == fingerprint
    _policy(repo, _roles(optimizer=[RAW], scorer=[fingerprint], dataset=[DATA], verdict=[VERDICT]))
    code, out = _lint(capsys, repo)
    assert code == 1 and out["findings"][0]["key"] == fingerprint


def test_advisories_never_block_unless_strict(repo, capsys):
    _policy(repo, _roles(optimizer=[OPT]))
    code, out = _lint(capsys, repo)
    assert code == 0 and out["ok"]
    assert {f["level"] for f in out["findings"]} == {"advisory"}
    assert [f["role"] for f in out["findings"]] == ["scorer", "dataset", "verdict"]
    code, out = _lint(capsys, repo, "--strict")
    assert code == 1 and out["blocking"] == 3


def test_no_policy_is_an_advisory(repo, capsys):
    code, out = _lint(capsys, repo)
    assert code == 0 and out["policy"] is None
    assert out["findings"][0]["code"] == "advisory:key-roles.no-policy"


@pytest.mark.parametrize("text", [
    "not toml [",
    "version = 2\n[roles]\n",
    "version = 1\n[roles]\nsigner = []\n",
    'version = 1\n[roles]\noptimizer = ["sha256:short"]\n',
])  # fmt: skip
def test_a_malformed_policy_is_a_fail(repo, capsys, text):
    _policy(repo, text)
    code, out = _lint(capsys, repo)
    assert code == 1 and out["findings"][0]["code"] == "fail:key-roles.malformed"


def test_promote_check_refuses_the_shared_key_and_passes_without_a_policy(repo, tmp_path):
    _key_roles.check_separation(repo.path, OPT)  # no policy: advisory only
    _policy(repo, _roles(optimizer=[OPT], scorer=[SCORE], dataset=[DATA], verdict=[VERDICT]))
    _key_roles.check_separation(repo.path, OPT)
    with pytest.raises(_key_roles.KeyRoleError, match="also holds a scorer key"):
        _key_roles.check_separation(repo.path, SCORE)
    other = tmp_path / "other.toml"
    other.write_bytes(_roles(optimizer=[OPT], verdict=[OPT]).encode())
    with pytest.raises(_key_roles.KeyRoleError, match="verdict"):
        _key_roles.check_separation(repo.path, DATA, policy=other)
