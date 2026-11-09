"""0.47 projects, second half: ``opentine.forge-claim`` and ``tine project fork`` (SPEC 4.23).

The 72-forge-claim family agrees in Python and the pyz (the TS verifier runs it
in ``ts/verifier``'s own suite); a match is never a pass. ``tine project claim``
writes ``.opentine/project`` and checks one; ``tine project fork`` copies the
run repository (never code) and ``verify --source`` checks ``forked_from``
against the source's history.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _forge_claim, _project, _schemas, cli
from opentine._cli_errors import VERIFICATION_FAILED
from opentine._pyz import _forgeclaim as pyz
from opentine._signed_record import RecordError
from opentine.repository import Repo, _project_ref
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "docs" / "conformance" / "vectors" / "72-forge-claim.json"
URL = "https://github.com/example/app.git"


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


# --- the conformance family in Python and the pyz --------------------------- #


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_68_family_agrees_in_python_and_the_pyz(verifier):
    cases = json.loads(FAMILY.read_text("utf-8"))["cases"]
    assert len(cases) == 11
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        try:
            if verifier == "python":
                got = _forge_claim.check(value["claim"], branch=value["branch"],
                                         project=value["project"])  # fmt: skip
            else:
                got = pyz.forge_claim_verify(value["claim"], value["branch"], value["project"])
        except (RecordError, pyz.Refused) as exc:
            assert case["expect"] == "reject", case["id"]
            assert exc.code == case["reason"], case["id"]
            continue
        assert case["expect"] == "accept", case["id"]
        assert got["state"] == "claimed-as-mirrored" and got["label"] == _forge_claim.LABEL


def test_the_record_schema_holds_the_accepted_claims():
    for case in json.loads(FAMILY.read_text("utf-8"))["cases"]:
        claim = tagged.decode(case["input"]["value"])["claim"]
        if case["expect"] == "accept":
            assert _schemas.validate(claim, "opentine-forge-claim-1")[1] == [], case["id"]


# --- tine project claim and fork --------------------------------------------- #


@pytest.fixture
def repo(tmp_path) -> Repo:
    store = Repo.init(tmp_path / "r")
    (store.path.parent / "owner.key").write_text("ab" * 32, encoding="utf-8")
    (store.path.parent / "forker.key").write_text("cd" * 32, encoding="utf-8")
    key = (store.path.parent / "owner.key").as_posix()
    code = cli.main(["project", "init", "app", "--tenant", "acme", "--forge", "github",
                     "--url", URL, "--forge-repo-id", "R_1", "--ed25519-key-file", key,
                     "--repo", store.path.parent.as_posix(), "--json"])  # fmt: skip
    assert not code
    return store


def test_claim_writes_the_file_and_checks_it(repo, tmp_path, capsys):
    capsys.readouterr()
    where = repo.path.parent.as_posix()
    code_dir = tmp_path / "code"
    code, out = _tine(capsys, "project", "claim", "--code", code_dir.as_posix(), "--repo", where,
                      "--json")  # fmt: skip
    body = json.loads(out)
    assert code == 0 and body["path"] == ".opentine/project" and body["branch"] == "main"
    written = (code_dir / ".opentine" / "project").read_bytes()
    assert written.endswith(b"\n") and json.loads(written) == body["claim"]
    genesis = _project.digest(_project_ref.history(repo)[0])
    assert body["claim"]["fingerprint"] == _forge_claim.fingerprint(genesis)
    assert _schemas.validate_output(body) == []
    claim_file = (code_dir / ".opentine" / "project").as_posix()
    code, out = _tine(capsys, "project", "claim", "--check", claim_file, "--repo", where, "--json")
    result = json.loads(out)["result"]
    assert code == 0 and result["label"] == "claimed by upstream (as mirrored)"
    assert _schemas.validate_output(json.loads(out)) == []
    code, _ = _tine(capsys, "project", "claim", "--check", claim_file, "--branch", "feature",
                    "--repo", where)  # fmt: skip
    assert code == VERIFICATION_FAILED
    code, _ = _tine(capsys, "project", "claim", "--missing", "--repo", where)
    assert code == VERIFICATION_FAILED


def _fork(capsys, repo: Repo, dest: Path, *extra: str) -> tuple[int, str]:
    key = (repo.path.parent / "forker.key").as_posix()
    return _tine(capsys, "project", "fork", dest.as_posix(), "--project-id", "app-fork",
                 "--ed25519-key-file", key, "--repo", repo.path.parent.as_posix(), "--json",
                 *extra)  # fmt: skip


def test_fork_copies_runs_never_the_manifest_and_verifies_against_its_source(
    repo, tmp_path, capsys
):
    from opentine.repository._paths import internal_path

    capsys.readouterr()
    from opentine.coord import _tasks

    _tasks.add(repo, "t1", "a coordination record the fork must keep")
    dest = tmp_path / "fork"
    code, out = _fork(capsys, repo, dest)
    body = json.loads(out)
    assert code == 0, out
    assert body["manifest"]["forked_from"] == "app" and body["fork_point"]["project_id"] == "app"
    assert _schemas.validate_output(body) == []
    copy = Repo.open(dest)
    task = repo.read_ref("coord/tasks/t1")
    assert task and copy.read_ref("coord/tasks/t1") == task and copy.has(task)
    assert not copy.has(repo.read_ref("project/manifest"))  # the source's manifest stays home
    assert copy.fsck().ok
    source = repo.path.parent.as_posix()
    code, out = _tine(capsys, "project", "verify", "--source", source, "--repo", dest.as_posix(),
                      "--json")  # fmt: skip
    fork = json.loads(out)["fork"]
    assert code == 0 and fork["state"] == "fork-verified" and fork["forked_from"] == "app"
    assert _schemas.validate_output(json.loads(out)) == []
    # a source that rewrote its history since the fork is refused
    point = json.loads(internal_path(copy.path, "project-fork.json").read_bytes())
    internal_path(copy.path, "project-fork.json").write_bytes(
        json.dumps({**point, "head": "blob:sha256:" + "9" * 64}).encode()
    )
    code, _ = _tine(capsys, "project", "verify", "--source", source, "--repo", dest.as_posix())
    assert code == VERIFICATION_FAILED


def test_a_fork_is_another_project_and_never_inherits_the_claim(repo, tmp_path, capsys):
    capsys.readouterr()
    code, _ = _fork(capsys, repo, tmp_path / "same", "--tenant", "acme")
    assert code == 0  # another project_id under the same tenant is a fork
    key = (repo.path.parent / "forker.key").as_posix()
    code, _ = _tine(capsys, "project", "fork", (tmp_path / "x").as_posix(), "--project-id",
                    "app", "--ed25519-key-file", key, "--repo",
                    repo.path.parent.as_posix())  # fmt: skip
    assert code != 0  # the same project_id and tenant is not a fork
    code_dir = tmp_path / "code"
    _tine(capsys, "project", "claim", "--code", code_dir.as_posix(), "--repo",
          repo.path.parent.as_posix())  # fmt: skip
    claim_file = (code_dir / ".opentine" / "project").as_posix()
    other = tmp_path / "other"
    assert _fork(capsys, repo, other, "--tenant", "beta")[0] == 0
    code, out = _tine(capsys, "project", "claim", "--check", claim_file, "--repo",
                      other.as_posix(), "--json")  # fmt: skip
    assert (
        code == VERIFICATION_FAILED and "forge-claim.wrong-project" in out + capsys.readouterr().err
    )


def test_verify_source_refuses_a_non_fork_and_a_wrong_source(repo, tmp_path, capsys):
    capsys.readouterr()
    where = repo.path.parent.as_posix()
    code, _ = _tine(capsys, "project", "verify", "--source", where, "--repo", where)
    assert code != 0  # not a fork
    dest = tmp_path / "fork"
    assert _fork(capsys, repo, dest)[0] == 0
    stranger = Repo.init(tmp_path / "s")
    key = (repo.path.parent / "owner.key").as_posix()
    cli.main(["project", "init", "zzz", "--tenant", "acme", "--forge", "github", "--url", URL,
              "--ed25519-key-file", key, "--repo", stranger.path.parent.as_posix()])  # fmt: skip
    code, _ = _tine(capsys, "project", "verify", "--source", stranger.path.parent.as_posix(),
                    "--repo", dest.as_posix())  # fmt: skip
    assert code == VERIFICATION_FAILED
