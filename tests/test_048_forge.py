"""0.48 forge integration: ``opentine.forge-check`` and ``tine forge publish`` (SPEC 4.24).

The 73-forge-check family agrees in Python and the pyz (the TS verifier runs
it in ``ts/verifier``'s own suite). ``tine forge publish`` is driven against
recorded forge answers (``tests/fixtures/forge``) through an in-process
transport: nothing here touches the network, and no token reaches stdout,
stderr or the record.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from opentine import _bundle, _forge_check, _forge_post, _schemas, cli
from opentine._cli_errors import VERIFICATION_FAILED
from opentine._pyz import _forgecheck as pyz
from opentine._signed_record import RecordError
from opentine.repository import Repo
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "docs" / "conformance" / "vectors" / "73-forge-check.json"
FIXTURES = ROOT / "tests" / "fixtures" / "forge"
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
SECRET = "tok-" + "s3cr3t" * 4


def _tine(capsys, *argv: str) -> tuple[int, str, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out, err = capsys.readouterr()
    return code, out, err


# --- the conformance family in Python and the pyz --------------------------- #


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_73_family_agrees_in_python_and_the_pyz(verifier):
    cases = json.loads(FAMILY.read_text("utf-8"))["cases"]
    assert len(cases) == 19
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        data = value["bundle_b64"]
        raw = None if data is None else base64.b64decode(data)
        try:
            if verifier == "python":
                got = _forge_check.check(value["check"], raw)
            else:
                got = pyz.forge_check_verify(value["check"], raw)
        except (RecordError, pyz.Refused) as exc:
            assert case["expect"] == "reject", case["id"]
            assert exc.code == case["reason"], case["id"]
            continue
        assert case["expect"] == "accept", case["id"]
        assert got["conclusion"] == value["check"]["conclusion"]


def test_the_record_schema_holds_the_accepted_checks():
    for case in json.loads(FAMILY.read_text("utf-8"))["cases"]:
        check = tagged.decode(case["input"]["value"])["check"]
        if case["expect"] == "accept":
            assert _schemas.validate(check, "opentine-forge-check-1")[1] == [], case["id"]


def test_percent_needs_no_floats():
    assert _forge_check.percent(308333) == "30.83%"
    assert _forge_check.percent(0) == "0.00%" and _forge_check.percent(1_000_000) == "100.00%"


# --- a code checkout, a run repository with a project, a bundle ------------- #


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)
    return done.stdout.decode().strip()


@pytest.fixture
def world(tmp_path, monkeypatch):
    for name in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{name}_NAME", "Forge Test")
        monkeypatch.setenv(f"GIT_{name}_EMAIL", "forge@example.com")
    for name in (
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY",
        "GITHUB_API_URL",
        "CI_PROJECT_ID",
        "CI_API_V4_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    code = tmp_path / "code"
    code.mkdir()
    _git(code, "init", "-q", "-b", "main")
    (code / "app.py").write_text("".join(f"line {n}\n" for n in range(1, 11)), "utf-8")
    _git(code, "add", "app.py")
    _git(code, "commit", "-q", "-m", "add app")
    sha = _git(code, "rev-parse", "HEAD")
    from opentine._line_attrib import PREFIX, SCHEMA

    ranges = [
        {"start_line": 2, "end_line": 4, "run": "run-a", "seq": 0, "model": "m"},
        {"start_line": 9, "end_line": 9, "run": "run-b", "seq": 1, "model": "m"},
    ]
    note = PREFIX + json.dumps({"schema": SCHEMA, "files": [{"path": "app.py", "ranges": ranges}]})
    _git(code, "notes", "--ref=refs/notes/tine", "add", "-f", "-m", note, sha)
    store = Repo.init(tmp_path / "runs")
    key = tmp_path / "owner.key"
    key.write_text("ab" * 32, encoding="utf-8")
    for forge, rid in (("github", "123456"), ("gitlab", "4321")):
        cli_args = [
            "project",
            "init" if forge == "github" else "link",
            "--forge",
            forge,
            "--url",
            f"https://{forge}.example/team/app.git",
            "--forge-repo-id",
            rid,
            "--ed25519-key-file",
            key.as_posix(),
            "--repo",
            store.path.parent.as_posix(),
        ]
        if forge == "github":
            cli_args[2:2] = ["app", "--tenant", "acme"]
        else:
            cli_args += ["--role", "secondary"]
        assert not cli.main(cli_args)
    bundle = tmp_path / "evidence.tbundle"
    bundle.write_bytes(_bundle.create(store))
    verify = tmp_path / "verify.json"
    verify.write_text(json.dumps({"ok": True, "path": "run.tine"}), "utf-8")
    return {
        "code": code,
        "sha": sha,
        "repo": store.path.parent,
        "bundle": bundle,
        "verify": verify,
        "tmp": tmp_path,
    }


class Recorded:
    """An httpx transport answering from a recorded fixture, keeping every request."""

    def __init__(self, name: str, sha: str) -> None:
        raw = json.loads((FIXTURES / f"{name}.json").read_text("utf-8"))
        self.answers = {k.replace("{commit}", sha): v for k, v in raw.items() if k != "_note"}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.answers.get(f"{request.method} {request.url.path}", (404, {}))
        return httpx.Response(status, json=body)

    def install(self, monkeypatch) -> Recorded:
        transport = httpx.MockTransport(self)
        monkeypatch.setattr(_forge_post, "client", lambda: httpx.Client(transport=transport))
        return self

    def sent(self, method: str, suffix: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path.endswith(suffix)]


def _common(world, forge: str, rid: str) -> list[str]:
    return [
        "forge",
        "publish",
        "--forge",
        forge,
        "--forge-repo-id",
        rid,
        "--code",
        world["code"].as_posix(),
        "--repo",
        world["repo"].as_posix(),
        "--verify",
        world["verify"].as_posix(),
        "--bundle",
        world["bundle"].as_posix(),
        "--bundle-url",
        "https://evidence.example/app/evidence.tbundle",
        "--json",
    ]


def test_dry_run_builds_the_record_and_plan_without_a_token(world, capsys):
    code, out, _ = _tine(
        capsys,
        *_common(world, "github", "123456"),
        "--repo-slug",
        "octo/app",
        "--pr",
        "7",
        "--dry-run",
    )
    body = json.loads(out)
    assert code == 0 and body["dry_run"] and body["posted"] == []
    check = body["check"]
    assert check["project_id"] == "app" and check["commit"] == world["sha"]
    assert check["ai"] == {"ai_lines": 4, "total_lines": 10, "share_ppm": 400000}
    assert check["verify"] == {"state": "verified", "runs": 1} and check["conclusion"] == "success"
    digest = "sha256:" + __import__("hashlib").sha256(world["bundle"].read_bytes()).hexdigest()
    assert check["bundle"]["digest"] == digest
    assert [row["start_line"] for row in check["overlay"]] == [2, 9]
    assert _forge_check.check(check, world["bundle"].read_bytes())["bundle"] == "matched"
    assert _schemas.validate_output(body) == []
    assert [step["target"] for step in body["plan"]] == ["check-run", "comment"]


def test_github_check_run_annotations_and_one_comment(world, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    fake = Recorded("github", world["sha"]).install(monkeypatch)
    code, out, err = _tine(
        capsys,
        *_common(world, "github", "123456"),
        "--repo-slug",
        "octo/app",
        "--pr",
        "7",
        "--api-url",
        "https://api.github.test",
    )
    assert code == 0, err
    body = json.loads(out)
    assert [(r["target"], r["state"]) for r in body["posted"]] == [
        ("check-run", "created"),
        ("comment", "updated"),
    ]
    (run,) = fake.sent("POST", "/check-runs")
    payload = json.loads(run.content)
    assert payload["conclusion"] == "success" and payload["head_sha"] == world["sha"]
    assert payload["details_url"] == "https://evidence.example/app/evidence.tbundle"
    notes = payload["output"]["annotations"]
    assert [(a["path"], a["start_line"], a["end_line"]) for a in notes] == [
        ("app.py", 2, 4),
        ("app.py", 9, 9),
    ]
    assert "40.00%" in payload["output"]["title"]
    (edit,) = fake.sent("PATCH", "/issues/comments/12")  # the bot's own, never mallory's
    assert json.loads(edit.content)["body"].startswith(_forge_post.MARKER)
    assert all(r.headers["Authorization"] == f"Bearer {SECRET}" for r in fake.requests)
    assert SECRET not in out and SECRET not in err
    assert _schemas.validate_output(body) == []


def test_github_app_requests_a_least_privilege_installation_token(world, capsys, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = world["tmp"] / "app.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fake = Recorded("github", world["sha"]).install(monkeypatch)
    code, out, err = _tine(
        capsys,
        *_common(world, "github", "123456"),
        "--repo-slug",
        "octo/app",
        "--app-id",
        "9",
        "--app-key-file",
        pem.as_posix(),
        "--installation-id",
        "77",
    )
    assert code == 0, err
    (grant,) = fake.sent("POST", "/access_tokens")
    assert json.loads(grant.content) == {"permissions": {"checks": "write"}}
    jwt = grant.headers["Authorization"].removeprefix("Bearer ")
    claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
    assert claims["iss"] == "9" and claims["exp"] - claims["iat"] == 600
    (run,) = fake.sent("POST", "/check-runs")
    assert run.headers["Authorization"] == "Bearer ghs_recordedInstallationToken"
    assert "ghs_recorded" not in out + err


def test_gitlab_status_and_a_new_mr_note(world, capsys, monkeypatch):
    monkeypatch.setenv("OPENTINE_GITLAB_TOKEN", SECRET)
    fake = Recorded("gitlab", world["sha"]).install(monkeypatch)
    argv = [a for a in _common(world, "gitlab", "4321") if a]
    argv[argv.index("--verify") + 1] = (world["tmp"] / "bad.json").as_posix()
    (world["tmp"] / "bad.json").write_text(json.dumps({"ok": False}), "utf-8")
    code, out, err = _tine(capsys, *argv, "--mr", "3", "--api-url", "https://gl.test/api/v4")
    assert code == 0, err
    body = json.loads(out)
    assert body["check"]["conclusion"] == "failure" and body["check"]["project_id"] == "app"
    (status,) = fake.sent("POST", f"/statuses/{world['sha']}")
    assert json.loads(status.content)["state"] == "failed"
    assert status.headers["PRIVATE-TOKEN"] == SECRET
    assert [r["state"] for r in body["posted"]] == ["created", "created"]  # not user 9's note
    assert SECRET not in out + err


def test_forgejo_status_is_a_warning_when_unverified(world, capsys, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORGEJO_TOKEN", SECRET)
    fake = Recorded("forgejo", world["sha"]).install(monkeypatch)
    argv = [
        "forge",
        "publish",
        "--forge",
        "forgejo",
        "--forge-repo-id",
        "team/app",
        "--repo-slug",
        "team/app",
        "--api-url",
        "https://forgejo.test/api/v1",
        "--pr",
        "5",
        "--code",
        world["code"].as_posix(),
        "--repo",
        world["tmp"].as_posix(),
        "--json",
    ]
    code, out, err = _tine(capsys, *argv)
    assert code == 0, err
    body = json.loads(out)
    assert body["check"]["conclusion"] == "neutral" and body["check"]["project_id"] is None
    (status,) = fake.sent("POST", f"/statuses/{world['sha']}")
    assert json.loads(status.content)["state"] == "warning"
    assert status.headers["Authorization"] == f"token {SECRET}"
    assert [r["state"] for r in body["posted"]] == ["created", "updated"]


def test_a_forge_failure_names_the_status_only(world, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    fake = Recorded("github", world["sha"]).install(monkeypatch)
    fake.answers["POST /repos/octo/app/check-runs"] = [403, {"message": f"bad {SECRET}"}]
    code, out, err = _tine(capsys, *_common(world, "github", "123456"), "--repo-slug", "octo/app")
    assert code != 0 and "HTTP 403" in err and SECRET not in out + err


def test_a_missing_token_is_named_not_guessed(world, capsys, monkeypatch):
    monkeypatch.delenv("OPENTINE_GITLAB_TOKEN", raising=False)
    Recorded("gitlab", world["sha"]).install(monkeypatch)
    code, _, err = _tine(capsys, *_common(world, "gitlab", "4321"))
    assert code != 0 and "OPENTINE_GITLAB_TOKEN" in err


def test_the_project_is_resolved_by_forge_repo_id(world, capsys):
    code, _, err = _tine(
        capsys, *_common(world, "github", "999"), "--repo-slug", "o/a", "--dry-run"
    )
    assert code != 0 and "forge_repo_id 999" in err
    code, _, err = _tine(
        capsys, *_common(world, "forgejo", "123456"), "--dry-run", "--repo-slug", "o/a"
    )
    assert code != 0 and "links no forgejo repository" in err


def test_a_bundle_that_does_not_verify_is_never_linked(world, capsys):
    world["bundle"].write_bytes(b"not a bundle")
    code, _, _ = _tine(
        capsys, *_common(world, "github", "123456"), "--repo-slug", "o/a", "--dry-run"
    )
    assert code == VERIFICATION_FAILED


def test_a_link_without_a_bundle_is_refused(world, capsys):
    argv = _common(world, "github", "123456")
    at = argv.index("--bundle")
    del argv[at : at + 2]
    code, _, err = _tine(capsys, *argv, "--repo-slug", "o/a", "--dry-run")
    assert code != 0 and "checkable offline" in err


def test_entire_writes_the_record_as_a_note_and_prints_the_push(world, capsys):
    out_file = world["tmp"] / "check.json"
    argv = [
        "forge",
        "publish",
        "--forge",
        "entire",
        "--forge-repo-id",
        "team/app",
        "--code",
        world["code"].as_posix(),
        "--repo",
        world["tmp"].as_posix(),
        "--run",
        "missing-run",
        "--dry-run",
        "--json",
    ]
    code, out, _ = _tine(capsys, *argv)
    assert code == 0 and [s["target"] for s in json.loads(out)["plan"]] == ["checkpoint", "note"]
    argv = [a for a in argv if a not in ("--run", "missing-run", "--dry-run")]
    code, out, err = _tine(capsys, *argv[:-1], "--out", out_file.as_posix(), "--json")
    assert code != 0 and "run not found: run-a" in err  # the overlay names run-a and run-b
    from opentine import _forge_entire

    record = json.loads(
        json.dumps(
            _forge_check.build(
                forge="entire",
                forge_repo_id="team/app",
                project_id=None,
                commit=world["sha"],
                verify_state="unverified",
                runs=0,
                ai_lines=4,
                total_lines=10,
            )
        )
    )
    rows = _forge_entire.publish(world["code"].as_posix(), record, [])
    note = _git(world["code"], "notes", f"--ref={_forge_entire.NOTES_REF}", "show", world["sha"])
    assert json.loads(note) == record
    assert _forge_entire.push_command(rows).endswith(
        f"{_forge_entire.NOTES_REF}:{_forge_entire.NOTES_REF}"
    )


def test_the_comment_is_inert_markdown(world):
    record = _forge_check.build(
        forge="github",
        forge_repo_id="1",
        project_id=None,
        commit=world["sha"],
        verify_state="verified",
        runs=1,
        ai_lines=1,
        total_lines=3,
        overlay=[{"path": "a`b|c.py", "start_line": 1, "end_line": 1, "run": None}],
    )
    text = _forge_post.summary(record)
    assert text.startswith(_forge_post.MARKER) and "`a'b\\|c.py`" in text and "33.33%" in text
