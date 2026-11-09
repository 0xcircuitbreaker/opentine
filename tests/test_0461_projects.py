"""0.46.1: project manifests, mirror states and ``caps.project`` (SPEC 4.16-4.18, 8.18).

The 65-project and 66-mirror-state families agree in Python and the pyz (the TS
verifier runs them in ``ts/verifier``'s conformance test); ``tine project``
writes a chain under ``project/manifest`` that only an owner can extend;
``tine serve`` stores manifests as signed, answers a uniform 404 and keeps them
out of the ref listing; a mirror state never passes anywhere.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _mirror_state, _project, _schemas, cli
from opentine._cli_errors import VERIFICATION_FAILED
from opentine._pyz import _project as pyz
from opentine._pyz_build import build_bytes
from opentine._signed_record import RecordError
from opentine.repository import Repo, _project_ref
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "docs" / "conformance" / "vectors"
SEED = "ab" * 32
URL = "https://github.com/example/app.git"


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def _cases(name: str) -> list[dict]:
    return json.loads((VECTORS / name).read_text("utf-8"))["cases"]


# --- the two conformance families in Python and the pyz --------------------- #


def _answer(verifier: str, op: str, value: dict):
    host = value.get("host_key")
    if op == "project.verify":
        check = _project.check if verifier == "python" else None
        if check:
            return check(
                value["manifest"], previous=value["previous"], owner_key=value["owner_key"]
            )
        return pyz.project_verify(value["manifest"], value["previous"], value["owner_key"])
    if op == "project.chain":
        if verifier == "python":
            return _project.chain(value["versions"], owner_key=value["owner_key"])
        return pyz.project_chain(value["versions"], value["owner_key"])
    if op == "mirror-state.verify":
        key = bytes.fromhex(host) if host else None
        if verifier == "python":
            return _mirror_state.check(value["state"], host_key=key, owners=value["owners"])
        return pyz.mirror_verify(value["state"], key, value["owners"])
    data = base64.b64decode(value["data_b64"])
    from opentine import _git_object

    check = _git_object.check if verifier == "python" else pyz.git_object_check
    return check(value["type"], data, value["oid"])


@pytest.mark.parametrize("verifier", ["python", "pyz"])
@pytest.mark.parametrize(("family", "count"), [("65-project.json", 28),
                                                ("66-mirror-state.json", 25)])  # fmt: skip
def test_the_65_and_66_families_agree_in_python_and_the_pyz(verifier, family, count):
    cases = _cases(family)
    assert len(cases) == count
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        if case["expect"] == "accept":
            assert _answer(verifier, case["op"], value) == case["output"], case["id"]
        else:
            with pytest.raises(ValueError) as caught:
                _answer(verifier, case["op"], value)
            assert caught.value.code == case["reason"], case["id"]  # type: ignore[attr-defined]


def test_no_mirror_state_vector_ever_passes():
    for case in _cases("66-mirror-state.json"):
        if case["op"] == "mirror-state.verify" and case["expect"] == "accept":
            assert case["output"]["state"] in ("host-statement", "host-statement-tofu")
            assert case["output"]["label"] == "host statement, not verified by you"
            assert "pass" not in json.dumps(case["output"])


def test_the_record_schemas_hold_the_accepted_vectors():
    for name, op, field in (("65-project.json", "project.verify", "manifest"),
                            ("66-mirror-state.json", "mirror-state.verify", "state")):  # fmt: skip
        for case in _cases(name):
            if case["op"] == op and case["expect"] == "accept":
                record = tagged.decode(case["input"]["value"])[field]
                stem, errors = _schemas.validate(record)
                assert errors == [] and stem in {"opentine-project-1", "opentine-mirror-state-1"}


def test_a_commitment_opens_only_with_its_url_and_salt():
    locator = {"commitment": _project.commitment(URL, b"s" * 32)}
    assert _project.opens(locator, URL, b"s" * 32)
    assert not _project.opens(locator, URL + "x", b"s" * 32)
    assert not _project.opens(locator, URL, b"t" * 32)
    with pytest.raises(ValueError):
        _project.commitment(URL, b"short")


# --- the built pyz, offline ------------------------------------------------- #


def test_the_built_pyz_checks_a_history_and_never_passes_a_mirror_state(tmp_path):
    cases = {case["id"]: tagged.decode(case["input"]["value"]) for case in
             _cases("65-project.json") + _cases("66-mirror-state.json")}  # fmt: skip
    history = tmp_path / "history.json"
    history.write_text(json.dumps({"versions": cases["project.chain.valid"]["versions"]}))
    state = tmp_path / "state.json"
    state.write_text(json.dumps(cases["mirror-state.host-statement"]["state"]))
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(cases["project.chain.reordered"]["versions"]))
    pyz_path = tmp_path / "tine-verify.pyz"
    pyz_path.write_bytes(build_bytes())

    def run(path: Path) -> tuple[int, dict]:
        argv = [sys.executable, "-I", "-S", pyz_path.as_posix(), path.as_posix()]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
        return done.returncode, json.loads(done.stdout)

    code, result = run(history)
    assert code == 0 and result["mode"] == "project" and result["verdict"] == "pass"
    assert result["checks"][0]["versions"] == 3
    code, result = run(state)
    assert result["mode"] == "mirror-state" and result["verdict"] == "host-statement"
    assert result["checks"][0]["outcome"] == "host-statement"
    code, result = run(broken)
    assert code == 1 and result["checks"][0]["reason"] == "project.chain-break"


# --- tine project, locally --------------------------------------------------- #


@pytest.fixture
def repo(tmp_path) -> Repo:
    store = Repo.init(tmp_path / "r")
    (store.path.parent / "owner.key").write_text(SEED, encoding="utf-8")
    (store.path.parent / "stranger.key").write_text("cd" * 32, encoding="utf-8")
    return store


def _init(capsys, repo: Repo, *extra: str) -> tuple[int, str]:
    key = (repo.path.parent / "owner.key").as_posix()
    return _tine(capsys, "project", "init", "app", "--tenant", "acme", "--forge", "github",
                 "--url", URL, "--forge-repo-id", "R_1", "--ed25519-key-file", key,
                 "--repo", repo.path.parent.as_posix(), "--json", *extra)  # fmt: skip


def test_init_link_show_history_verify(repo, capsys):
    code, out = _init(capsys, repo)
    assert code == 0, out
    first = json.loads(out)
    assert first["project"] == {"project_id": "app", "tenant": "acme", "seq": 0,
                                "visibility": "public"}  # fmt: skip
    assert repo.read_ref("project/manifest") == first["digest"]
    key = (repo.path.parent / "owner.key").as_posix()
    code, out = _tine(capsys, "project", "link", "--role", "secondary", "--forge", "git",
                      "--url", "ssh://git.example.org/app.git", "--ed25519-key-file", key,
                      "--repo", repo.path.parent.as_posix(), "--json")  # fmt: skip
    assert code == 0, out
    second = json.loads(out)["manifest"]
    assert second["prev"] == first["digest"] and [s["role"] for s in second["slots"]] == [
        "primary",
        "secondary",
    ]
    code, out = _tine(capsys, "project", "history", "--repo", repo.path.parent.as_posix(), "--json")
    assert [v["seq"] for v in json.loads(out)["versions"]] == [0, 1]
    owner = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
    pinned = owner.public_key().public_bytes_raw().hex()
    code, out = _tine(capsys, "project", "verify", "--owner-key", pinned,
                      "--repo", repo.path.parent.as_posix(), "--json")  # fmt: skip
    assert code == 0 and json.loads(out)["result"]["state"] == "verified"
    for document in (first, json.loads(out)):
        assert _schemas.validate_output(document) == []
    assert repo.fsck().ok


def test_only_an_owner_can_extend_the_chain(repo, capsys):
    assert _init(capsys, repo)[0] == 0
    before = repo.read_ref("project/manifest")
    stranger = (repo.path.parent / "stranger.key").as_posix()
    code, _ = _tine(
        capsys,
        "project",
        "link",
        "--forge",
        "github",
        "--url",
        URL,
        "--ed25519-key-file",
        stranger,
        "--repo",
        repo.path.parent.as_posix(),
    )
    assert code == VERIFICATION_FAILED
    assert repo.read_ref("project/manifest") == before


def test_a_private_project_holds_no_url(repo, capsys):
    code, out = _init(capsys, repo, "--visibility", "private")
    assert code == 0, out
    manifest = json.loads(out)["manifest"]
    assert URL not in json.dumps(manifest) and "example/app" not in json.dumps(manifest)
    locator = manifest["slots"][0]["locator"]
    saved = _project_ref.locators(repo)[locator["commitment"]]
    assert saved["url"] == URL
    assert _project.opens(locator, URL, bytes.fromhex(saved["salt"]))


def test_a_public_project_over_a_private_upstream_is_refused(repo, capsys):
    code, _ = _init(capsys, repo, "--upstream-visibility", "private")
    assert code == VERIFICATION_FAILED and _project_ref.read(repo) is None


def test_the_project_namespace_holds_only_a_manifest(repo):
    run_blob = repo.put("blob", b"not a manifest", redact=False)
    with pytest.raises(ValueError):
        repo.update_ref("project/manifest", run_blob)
    with pytest.raises(ValueError):
        repo.update_ref("project/other", run_blob)


# --- tine serve: caps.project ----------------------------------------------- #


def _remote(tmp_path, monkeypatch):
    from opentine.remote import (
        FilesystemObjectStore,
        Identity,
        LocalKeyProvider,
        RemoteApp,
        RemoteService,
        RoleAuthorizationPolicy,
        SQLiteBackend,
        StaticTokenIdentityProvider,
    )
    from opentine.repository import _http
    from opentine.repository import client as repository_client

    identities = StaticTokenIdentityProvider({
        "w": Identity("w", "acme", ("writer",)), "r": Identity("r", "acme", ("reader",)),
        "o": Identity("x", "other", ("admin",)),
    })  # fmt: skip
    service = RemoteService(
        FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32)),
        SQLiteBackend(tmp_path / "remote.sqlite3"),
        identities,
        RoleAuthorizationPolicy(),
    )
    app = RemoteApp(service, tmp_path / "state")

    def http(token: str | None = "w", **_kw) -> httpx.Client:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx.Client(base_url="http://remote", transport=httpx.WSGITransport(app=app),
                            headers=headers)  # fmt: skip

    monkeypatch.setattr(repository_client, "_client", lambda base, token, **kw: http(token))
    monkeypatch.setattr(_http, "client", lambda base, token, **kw: http(token))
    return service, http


def test_push_show_and_history_against_tine_serve(repo, tmp_path, monkeypatch, capsys):
    service, http = _remote(tmp_path, monkeypatch)
    caps = service.capabilities()
    assert caps["project"]["path"] == "project" and caps["social_export"]["path"] == "social"
    assert not {"mirror", "upload_pack", "receive_pack"} & set(caps)
    assert _init(capsys, repo)[0] == 0
    where = repo.path.parent.as_posix()
    remote = ("--remote", "https://remote", "--tenant", "acme", "--token", "w")
    code, out = _tine(capsys, "project", "push", *remote, "--repo", where, "--json")
    assert code == 0 and json.loads(out)["sent"] == 1, out
    code, out = _tine(capsys, "project", "push", *remote, "--repo", where, "--json")
    assert code == 0 and json.loads(out)["sent"] == 0
    code, out = _tine(capsys, "project", "verify", *remote, "--repo", where, "--json")
    assert code == 0 and json.loads(out)["result"]["head"] == repo.read_ref("project/manifest")
    assert "project/manifest" not in http().get("/v1/tenants/acme/refs").json()["refs"]
    forged = http().put(
        "/v1/tenants/acme/refs/project%2Fmanifest",
        json={"new": repo.read_ref("project/manifest"), "expected_old": None},
    )
    assert forged.status_code == 400
    assert http().get("/v1/tenants/acme/social").json() == {"stars": 0, "watches": 0}


def test_remote_reads_are_a_uniform_404_and_writes_need_a_writer(repo, tmp_path, monkeypatch):
    _service, http = _remote(tmp_path, monkeypatch)
    empty = http("r").get("/v1/tenants/acme/project")
    other = http("o").get("/v1/tenants/acme/project")
    nowhere = http("o").get("/v1/tenants/nobody/project")
    assert empty.status_code == 404 and empty.json() == {"error": "not found"}
    assert (other.status_code, other.content) == (nowhere.status_code, nowhere.content)
    assert other.status_code in (403, 404)
    anonymous = http(None).get("/v1/tenants/acme/project")
    missing = http(None).get("/v1/tenants/nobody/project")
    assert anonymous.status_code == 401 and anonymous.content == missing.content
    owner = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
    slot = {
        "role": "primary",
        "forge": "github",
        "forge_repo_id": None,
        "upstream_visibility": "public",
        "locator": {"url": URL},
        "default_branch": "main",
    }
    record = _project.sign(_project.build("app", "acme", owners=[
        owner.public_key().public_bytes_raw().hex()], slots=[slot]), owner)  # fmt: skip
    body = {"expected_old": None, "manifest": record}
    assert http("r").put("/v1/tenants/acme/project", json=body).status_code == 403
    elsewhere = _project.sign(_project.build("app", "other", owners=record["owners"],
                                             slots=[slot]), owner)  # fmt: skip
    wrong_tenant = http("w").put("/v1/tenants/acme/project",
                                 json={"expected_old": None, "manifest": elsewhere})  # fmt: skip
    assert wrong_tenant.status_code == 400
    done = http("w").put("/v1/tenants/acme/project", json=body)
    assert done.status_code == 200 and done.json()["digest"] == _project.digest(record)
    assert http("r").get("/v1/tenants/acme/project").json()["manifest"] == record
    page = http("r").get("/v1/tenants/acme/project/history?cursor=1").json()
    assert page == {"versions": [], "next_cursor": None, "total": 1}
    assert http("r").get("/v1/tenants/acme/project/history?cursor=x").status_code == 400


def test_a_pinned_remote_project_must_match(repo, tmp_path, monkeypatch, capsys):
    _service, _http = _remote(tmp_path, monkeypatch)
    assert _init(capsys, repo)[0] == 0
    where = repo.path.parent.as_posix()
    from opentine import _porcelain_config as porcelain

    porcelain.save(
        repo.path,
        {
            "remotes": {"origin": {"url": "https://remote", "tenant": "acme", "project": "other"}},
            "config": {},
        },
    )
    monkeypatch.setattr(porcelain, "trusted", lambda _path: True)
    code, _ = _tine(capsys, "project", "push", "--token", "w", "--repo", where)
    assert code != 0


def test_old_clients_fetch_past_a_project(repo, tmp_path, monkeypatch, capsys):
    """A remote with a project still serves refs, fetch and clone exactly as before."""
    from opentine.graph import Run, StepKind
    from opentine.repository import client as repository_client

    _service, _http_client = _remote(tmp_path, monkeypatch)
    run = Run(id="r1", model_info="m", user_prompt="p")
    run.add_step(StepKind.done, {"text": "t"})
    oid = repo.put_run(run, ref="heads/main").run_id
    assert _init(capsys, repo)[0] == 0
    repository_client.push(repo, "https://remote", tenant="acme", token="w")
    remote = ("--remote", "https://remote", "--tenant", "acme", "--token", "w")
    assert _tine(capsys, "project", "push", *remote, "--repo", repo.path.parent.as_posix())[0] == 0
    local = Repo.init(tmp_path / "old")
    repository_client.fetch(local, "https://remote", tenant="acme", token="w")
    assert local.has(oid) and local.read_ref("project/manifest") is None


def test_check_refuses_a_record_error_with_its_code():
    with pytest.raises(RecordError) as caught:
        _project.check({"kind": "opentine.project"})
    assert caught.value.code == "project.malformed"
