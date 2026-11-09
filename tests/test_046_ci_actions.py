"""0.46: the CI gate (actions/gate, the GitLab component) run locally, offline."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _ci_comment, _ci_gate, _ci_run, _schemas, cli
from opentine.core import Run, RunStatus, StepKind
from opentine.remote._vsa import TrustPolicyAdmission
from opentine.remote.interfaces import Identity
from opentine.signing import generate_ed25519

ROOT = Path(__file__).resolve().parents[1]
OID = "run:" + "ab" * 32
SECRET = "ghs_SUPERSECRETTOKEN0123456789"


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _vsa(tmp_path: Path, policy_check=None) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    admission = TrustPolicyAdmission(private_key=key)
    admission.admit(Identity("ci", "acme", ("writer",)), "update_ref",
                    {"tenant": "acme", "name": "tags/v1", "new": OID})  # fmt: skip
    envelope = tmp_path / "vsa.json"
    envelope.write_text(json.dumps(admission.recent[0]), encoding="utf-8")
    pub = tmp_path / "server.pub"
    from cryptography.hazmat.primitives import serialization

    pub.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))  # fmt: skip
    return envelope, pub


def _signed_run(room: Path) -> Path:
    run = Run(id="gate-run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    seed, public = generate_ed25519()
    (room / "ci.pub").write_text(public + "\n", encoding="utf-8")
    run.save(room / "good.tine", sign_key=seed, sign_algorithm="ed25519")
    unsigned = Run(id="forged", model_info="mock-model", user_prompt="p")
    unsigned.add_step(StepKind.done, {"text": "done"})
    unsigned.status = RunStatus.completed
    unsigned.save(room / "forged.tine")
    return room / "good.tine"


def test_the_gate_runs_tine_verify_and_checks_the_vsa(room: Path):
    good = _signed_run(room)
    broken = room / "broken.tine"
    broken.write_text("{}", encoding="utf-8")
    envelope, pub = _vsa(room)
    env = {"RUNS": f"{good.as_posix()}\n", "PUBKEY": str(room / "ci.pub"),
           "VSA": str(envelope), "VSA_KEY": str(pub), "VSA_RESOURCE": "tine://acme/tags/v1",
           "SUBJECT": OID, "VSA_LEVELS": "OPENTINE_ADMITTED", "OUT": str(room / "out"),
           "GITHUB_OUTPUT": str(room / "gh-out")}  # fmt: skip
    assert _ci_run.main(env) == 0
    summary = json.loads((room / "out" / "summary.json").read_text("utf-8"))
    assert summary["ok"] and [c["check"] for c in summary["checks"]] == ["verify", "vsa"]
    assert _schemas.validate(summary)[1] == []
    assert "ok=true" in (room / "gh-out").read_text("utf-8")
    comment = (room / "out" / "comment.md").read_text("utf-8")
    assert comment.startswith(_ci_gate.MARKER) and "passed" in comment

    env["RUNS"] = f"{good.as_posix()}\n{broken.as_posix()}"
    env["VSA_POLICY"] = "opentine:trust-policy/prod"
    assert _ci_run.main(env) == _ci_gate.FAILED
    summary = json.loads((room / "out" / "summary.json").read_text("utf-8"))
    assert [c["ok"] for c in summary["checks"]] == [True, False, False]
    assert summary["checks"][2]["class"] == "wrong-policy"
    assert "ok=false" in (room / "gh-out").read_text("utf-8")


def test_the_gate_fails_closed_on_unpinned_forged_runs_and_replayed_vsas(room: Path):
    _signed_run(room)
    envelope, pub = _vsa(room)
    out = str(room / "out")
    # A forged, unsigned run passes `tine verify` on internal consistency alone; without a
    # pinned key the gate refuses it, and under the key the forgery fails.
    assert _ci_run.main({"RUNS": "forged.tine", "OUT": out}) == _ci_gate.FAILED
    summary = json.loads((room / "out" / "summary.json").read_text("utf-8"))
    assert summary["checks"][0]["class"] == "unpinned"
    assert _schemas.validate(summary)[1] == []
    env = {"RUNS": "forged.tine", "PUBKEY": "ci.pub", "OUT": out}
    assert _ci_run.main(env) == _ci_gate.FAILED
    # A VSA another tenant's ref earned for the same object is not this resource's.
    env = {"VSA": str(envelope), "VSA_KEY": str(pub), "SUBJECT": OID, "OUT": out,
           "VSA_RESOURCE": "tine://other/tags/v1"}  # fmt: skip
    assert _ci_run.main(env) == _ci_gate.FAILED
    summary = json.loads((room / "out" / "summary.json").read_text("utf-8"))
    assert summary["checks"][0]["class"] == "wrong-resource"
    assert _schemas.validate(summary)[1] == []


def test_eval_outputs_and_a_custom_tine_command(room: Path, monkeypatch):
    fake = room / "fake_tine.py"
    fake.write_text(
        "import json, sys\n"
        "print(json.dumps({'command': 'eval verify', 'ok': sys.argv[3] == 'good'}))\n",
        encoding="utf-8",
    )
    tine = f'"{Path(sys.executable).as_posix()}" "{fake.as_posix()}"'
    env = {"EVAL_DIRS": "good", "EVAL_PUBKEY": "k.pub", "OPENTINE_TINE": tine,
           "OUT": str(room / "o")}  # fmt: skip
    assert _ci_run.main(env) == 0
    env["EVAL_DIRS"] = "good\nbad"
    assert _ci_run.main(env) == _ci_gate.FAILED
    assert _ci_run.main({"OUT": str(room / "o")}) == _ci_gate.FAILED  # no checks never passes


def test_the_comment_is_inert_and_carries_no_secrets(room: Path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    hostile = room / "v.json"
    name = "x`|<script>@{{ secrets.TOKEN }}$(id)\n| injected |"
    hostile.write_text(json.dumps({"command": "verify", "ok": False, "path": name}), "utf-8")
    out = room / "c.md"
    code = _ci_gate.main(["--verify", str(hostile), "--verify", str(room / "missing.json"),
                          "--comment", str(out)])  # fmt: skip
    assert code == _ci_gate.FAILED
    text = out.read_text("utf-8")
    assert SECRET not in text  # the environment never reaches the comment
    body_rows = text.splitlines()[5:]
    assert len(body_rows) == 2  # the newline in the name did not add a table row
    assert not re.search(r"[`<>$|{}]", body_rows[0].split("`")[1])
    assert "unreadable" in body_rows[1]
    assert len(_ci_gate.clean("a" * 500)) == 120
    assert _ci_gate.main(["--vsa", "x.json"]) == _ci_gate.USAGE


def test_the_vsa_key_may_be_raw_or_base64url(room: Path):
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    (room / "raw.key").write_bytes(key)
    import base64

    (room / "b64.key").write_text(base64.urlsafe_b64encode(key).decode().rstrip("=") + "\n")
    assert _ci_gate.public_key_bytes(str(room / "raw.key")) == key
    assert _ci_gate.public_key_bytes(str(room / "b64.key")) == key


class _Api:
    def __init__(self, existing: list[dict], status: int = 200):
        self.existing, self.status, self.seen = existing, status, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append((request.method, request.url.path, dict(request.headers)))
        if request.method == "GET" and request.url.path.endswith("/user"):
            return httpx.Response(200, json={"id": 77, "username": "project_bot"})
        if request.method == "GET":
            return httpx.Response(self.status, json=self.existing)
        return httpx.Response(201 if request.method == "POST" else 200, json={})


def _env(**extra) -> dict[str, str]:
    return {"GITHUB_TOKEN": SECRET, "GITHUB_REPOSITORY": "acme/app", "OPENTINE_PR": "7",
            "GITHUB_API_URL": "https://api.github.test", **extra}  # fmt: skip


def test_the_comment_is_created_then_updated_in_place():
    api = _Api([{"id": 1, "body": "unrelated"}])
    client = httpx.Client(transport=httpx.MockTransport(api))
    assert _ci_comment.upsert("github", "body", _env(), client) == "created"
    assert api.seen[-1][:2] == ("POST", "/repos/acme/app/issues/7/comments")
    assert api.seen[-1][2]["authorization"] == f"Bearer {SECRET}"
    # A PR author pasting the marker into their own comment cannot capture the update.
    api.existing.append({"id": 41, "body": _ci_gate.MARKER + "\nfake passed",
                         "user": {"login": "mallory"}})  # fmt: skip
    assert _ci_comment.upsert("github", "body", _env(), client) == "created"
    api.existing.append({"id": 42, "body": _ci_gate.MARKER + "\nold",
                         "user": {"login": "github-actions[bot]"}})  # fmt: skip
    assert _ci_comment.upsert("github", "body", _env(), client) == "updated"
    assert api.seen[-1][:2] == ("PATCH", "/repos/acme/app/issues/comments/42")

    gitlab = _Api(
        [
            {"id": 8, "body": _ci_gate.MARKER, "author": {"id": 5}},
            {"id": 9, "body": _ci_gate.MARKER, "author": {"id": 77}},
        ]
    )
    env = {"OPENTINE_GITLAB_TOKEN": SECRET, "CI_PROJECT_ID": "3", "CI_MERGE_REQUEST_IID": "5",
           "CI_API_V4_URL": "https://gitlab.test/api/v4"}  # fmt: skip
    client = httpx.Client(transport=httpx.MockTransport(gitlab))
    assert _ci_comment.upsert("gitlab", "b", env, client) == "updated"
    assert gitlab.seen[-1][:2] == ("PUT", "/api/v4/projects/3/merge_requests/5/notes/9")
    assert gitlab.seen[-1][2]["private-token"] == SECRET


def test_comment_failures_never_print_the_token(room: Path, monkeypatch, capsys):
    (room / "c.md").write_text("hi", encoding="utf-8")
    for name, value in _env().items():
        monkeypatch.setenv(name, value)
    client = httpx.Client(transport=httpx.MockTransport(_Api([], status=403)))
    # A comment that cannot be written (a fork PR's read-only token) never fails the job.
    assert _ci_comment.main(["github", "--body", str(room / "c.md")], client=client) == 0
    monkeypatch.delenv("OPENTINE_PR")
    assert _ci_comment.main(["github", "--body", str(room / "c.md")]) == 0  # skipped
    captured = capsys.readouterr()
    assert "HTTP 403" in captured.err and SECRET not in captured.out + captured.err


def _actions() -> dict[str, dict]:
    yaml = pytest.importorskip("yaml")
    found = {}
    for path in sorted((ROOT / "actions").rglob("*.yml")):
        text = path.read_text("utf-8")
        docs = list(yaml.safe_load_all(text))
        found[path.relative_to(ROOT).as_posix()] = {"text": text, "docs": docs}
    return found


def test_actions_pin_opentine_and_never_interpolate_inputs_into_scripts():
    found = _actions()
    assert set(found) == {"actions/gate/action.yml", "actions/preserve-notes/action.yml",
                          "actions/gitlab/templates/opentine-gate.yml"}  # fmt: skip
    for name, item in found.items():
        assert "permissions" in item["text"].lower() or "least privilege" in item["text"].lower()
        if name.startswith("actions/gitlab"):
            spec, job = item["docs"]
            assert re.fullmatch(
                r"\d+\.\d+\.\d+", spec["spec"]["inputs"]["opentine-version"]["default"]
            )
            (body,) = job.values()
            assert not any("$[[" in line for line in body["script"]), name
            continue
        action = item["docs"][0]
        assert action["runs"]["using"] == "composite"
        assert re.fullmatch(r"\d+\.\d+\.\d+", action["inputs"]["opentine-version"]["default"])
        for step in action["runs"]["steps"]:
            assert "uses" not in step  # no third-party action to pin
            assert "${{" not in step["run"], (name, step["name"])
    gate = found["actions/gate/action.yml"]["docs"][0]
    assert "python -m opentine._ci_run" in gate["runs"]["steps"][1]["run"]
