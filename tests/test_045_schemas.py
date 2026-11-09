"""0.45: published JSON Schemas, ``tine schema``, ``tine help --json``.

Every ``--json`` output driven here must validate against the CLI envelope and,
when one is published, its own schema (``_schemas.COMMAND_SCHEMAS``); the
in-house validator is cross-checked against ``jsonschema`` when it is
installed. ``docs/schemas`` must be exactly what ``scripts/gen_schemas.py``
renders.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import _jsonschema, _schemas, cli
from opentine.core import Run, RunStatus, StepKind

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "compat" / "v0_5_0" / "repo"
REPORT_VECTORS = ROOT / "tests" / "fixtures" / "redaction_report" / "vectors.json"


def _tine(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="schema_run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    shutil.copytree(GOLDEN, tmp_path / "repo")
    vectors = json.loads(REPORT_VECTORS.read_text("utf-8"))["cases"]
    signed = next(case["report"] for case in vectors if case["id"].endswith("ed25519"))
    (tmp_path / "report.json").write_text(json.dumps(signed), encoding="utf-8")
    (tmp_path / "purge.key").write_text("ab" * 32, encoding="utf-8")  # 0.46: tine purge
    item = {"id": "q", "input": "1", "expected": "1", "output": "1", "run": "run:x"}  # 0.47
    (tmp_path / "repo" / "d.jsonl").write_text(json.dumps(item) + "\n", encoding="utf-8")
    (tmp_path / "evals.toml").write_text(
        '[[eval]]\nname = "smoke"\ndataset = "d.jsonl"\nscorer = "exact"\n', encoding="utf-8"
    )
    if shutil.which("git"):  # 0.47: tine experts blames a committed tree
        for role in ("AUTHOR", "COMMITTER"):
            monkeypatch.setenv(f"GIT_{role}_NAME", "schema")
            monkeypatch.setenv(f"GIT_{role}_EMAIL", "schema@example.invalid")
        code = tmp_path / "code"
        code.mkdir()
        (code / "a.txt").write_text("one\n", encoding="utf-8")
        for argv in (("init", "-q"), ("add", "a.txt"), ("commit", "-q", "-m", "c")):
            subprocess.run(["git", "-c", "commit.gpgsign=false", *argv], cwd=code, check=True,
                           capture_output=True)  # fmt: skip
    return tmp_path


def _jsonschema_errors(document: object, name: str) -> list[str] | None:
    """The reference validator's verdict, or None when it is not installed."""
    try:
        import jsonschema
        from referencing import Registry, Resource
    except ImportError:
        return None
    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in _schemas.SCHEMAS.values()
    )
    validator = jsonschema.Draft202012Validator(_schemas.get(name), registry=registry)
    return [e.message for e in validator.iter_errors(document)]


PURGED = "blob:sha256:06447dcb58c2856bcf2e91ebde6c6dc8d308026b314421ba25eae9b39ce16446"
# 0.47: the golden repository's main tip, absent from its heads/experiment fork.
MAIN_TIP = "event:sha256:6dc1725e0e6fafee882214a92946453481af791810e4b8cc3cea6417d21cbe1f"
RUN0 = "run:sha256:be292c795e4d4c484dd65313e8556098ce724bdc7bae5722c6125c49c651db36"

# The --json invocations the web reads; each is (argv, expected command or tag).
DRIVEN = (
    (("show", "run.tine", "--json"), "tine-cli-show-1"),
    (("verify", "run.tine", "--json"), "tine-cli-verify-1"),
    (("verify", "run.tine", "--offline", "--json"), "tine-verify-report-2"),
    (("cost", "run.tine", "--json"), "tine-cli-cost-1"),
    (("ls", "--json"), "tine-cli-runs-1"),
    (("search", "mock", "--json"), "tine-cli-runs-1"),
    (("blame", "x.py", "--json"), "tine-blame-1"),
    (("repo-show", "heads/main", "--repo", "repo", "--json"), "tine-repo-show-1"),
    (("repo-search", "--repo", "repo", "--json"), "tine-search-results-1"),
    (("repo-log", "heads/main", "--repo", "repo", "--json"), "tine-cli-envelope-1"),
    (("pricing", "list", "--json"), "tine-cli-envelope-1"),
    (("schema", "list", "--json"), "tine-cli-envelope-1"),
    (("help", "--json"), "tine-help-1"),
    (("help", "no-such-command", "--json"), "tine-cli-envelope-1"),
    (("schema", "show", "tine-run-1", "--json"), "tine-cli-envelope-1"),
    (("schema", "show", "no-such", "--json"), "tine-cli-envelope-1"),
    (("show", "no-such-run", "--json"), "tine-cli-envelope-1"),
    (("bisect", "--help-not-a-flag", "--json"), None),
    (("doctor", "--repo", "repo", "--json"), "tine-cli-doctor-1"),
    (("redact", "check", "--repo", "repo", "--json"), "tine-cli-redact-check-1"),
    (("redact", "verify", "report.json", "--json"), "tine-cli-redact-verify-1"),
    (("redact", "rules", "--json"), "tine-redaction-rules-1"),
    (
        (
            "open",
            "run:sha256:" + "a" * 64,
            "--web-url",
            "https://w.invalid",
            "--tenant",
            "acme",
            "--json",
        ),
        "tine-cli-open-1",
    ),  # fmt: skip
    (("redact", "check", "--repo", "repo", "--run", "no-such", "--json"), "tine-cli-envelope-1"),
    (
        (
            "purge",
            PURGED,
            "--reason",
            "erasure",
            "--key-file",
            "purge.key",
            "--repo",
            "repo",
            "--json",
        ),
        "tine-cli-purge-1",
    ),
    (("purge", "--list", "--repo", "repo", "--json"), "tine-cli-purge-list-1"),
    (
        ("hook", "resume", "--agent", "codex", "--session", "s1", "--message", "go", "--dry-run"),
        "tine-cli-hook-resume-1",
    ),
    (
        (
            "project",
            "init",
            "demo",
            "--tenant",
            "acme",
            "--forge",
            "github",
            "--url",
            "https://github.com/example/app.git",
            "--ed25519-key-file",
            "purge.key",
            "--repo",
            "repo",
            "--json",
        ),
        "tine-cli-project-1",
    ),  # fmt: skip
    (("merge", "heads/experiment", "heads/main", "--repo", "repo", "--json"), "tine-cli-merge-1"),
    (
        ("pick", "heads/experiment", MAIN_TIP, "--repo", "repo", "--json"),
        "tine-cli-pick-1",
    ),
    (
        ("merge-queue", "init", "q", "--target", "heads/main", "--repo", "repo", "--json"),
        "tine-cli-merge-queue-1",
    ),
    (
        (
            "merge-queue",
            "approve",
            RUN0,
            "--target",
            "heads/main",
            "--approver",
            "alice",
            "--ed25519-key-file",
            "purge.key",
            "--json",
        ),
        "tine-cli-merge-queue-1",
    ),
    (
        (
            "review",
            "create",
            "demo",
            "--title",
            "Demo",
            "--gate",
            "ship",
            "--ed25519-key-file",
            "purge.key",
            "--repo",
            "repo",
            "--json",
        ),
        "tine-cli-review-1",
    ),  # fmt: skip
    (
        (
            "prompt",
            "push",
            "review",
            "--template",
            "Review {{diff}}",
            "--key",
            "purge.key",
            "--repo",
            "repo",
            "--json",
        ),
        "tine-cli-prompt-1",
    ),
    (
        (
            "memory",
            "add",
            "testing",
            "Use the venv python",
            "--key",
            "purge.key",
            "--repo",
            "repo",
            "--json",
        ),
        "tine-cli-memory-1",
    ),
    (
        ("eval", "ci", "--config", "evals.toml", "--key", "purge.key", "--repo", "repo", "--json"),
        "tine-cli-eval-ci-1",
    ),
    (("plugins", "list", "--json"), "tine-cli-plugins-1"),
    (("experts", "code", "--json"), "tine-experts-1"),
    (
        ("forge", "publish", "--forge", "gitlab", "--forge-repo-id", "4321", "--code", "code")
        + ("--repo", "repo", "--dry-run", "--json"),
        "tine-cli-forge-1",
    ),
    (("code-graph", "--repo", "repo", "--json"), "tine-graph-1"),  # 0.48
    (("compliance", "list", "--json"), "tine-cli-compliance-list-1"),  # 0.48
    (
        ("compliance", "check", "run.tine", "--profile", "eu-ai-act", "--json"),
        "tine-cli-compliance-check-1",
    ),  # fmt: skip
    (("audit-kit", "build", "run.tine", "--out", "kit", "--json"), "tine-cli-audit-kit-build-1"),
    (("audit-kit", "verify", "kit", "--json"), "tine-cli-audit-kit-verify-1"),  # 0.49
)


@pytest.mark.parametrize(("argv", "expected"), DRIVEN, ids=[" ".join(a) for a, _ in DRIVEN])
def test_every_driven_json_output_validates(monkeypatch, capsys, room, argv, expected):
    if argv[0] in ("experts", "forge") and shutil.which("git") is None:
        pytest.skip("tine experts blames with git")
    if argv[:2] == ("audit-kit", "verify"):  # 0.49: verify needs a kit to check
        _tine(monkeypatch, capsys, "audit-kit", "build", "run.tine", "--out", "kit", "--json")
    _code, out = _tine(monkeypatch, capsys, *argv)
    if expected is None:  # a usage error prints no JSON object at all
        assert not out.strip().startswith("{") or "error" in json.loads(out)
        return
    document = json.loads(out)
    assert _schemas.detect(document) == expected
    assert _schemas.validate_output(document) == []
    reference = _jsonschema_errors(document, expected)
    assert reference in (None, []), reference


def test_every_command_schema_is_driven():
    driven = {expected for _argv, expected in DRIVEN}
    assert set(_schemas.COMMAND_SCHEMAS.values()) <= driven


def test_every_schema_is_well_formed_and_in_the_subset():
    for name, schema in _schemas.SCHEMAS.items():
        assert schema["$id"].endswith(f"/{name}.schema.json"), name
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert _jsonschema.check_schema(schema) == [], name
    try:
        import jsonschema
    except ImportError:
        return
    for schema in _schemas.SCHEMAS.values():
        jsonschema.Draft202012Validator.check_schema(schema)


def test_docs_schemas_are_the_rendered_definitions():
    folder = ROOT / "docs" / "schemas"
    if not folder.is_dir():  # pragma: no cover - installed distribution
        pytest.skip("docs/ is not part of an installed distribution")
    published = {p.name for p in folder.glob("*.schema.json")}
    assert published == {f"{n}.schema.json" for n in _schemas.SCHEMAS}
    for name, schema in _schemas.SCHEMAS.items():
        text = (folder / f"{name}.schema.json").read_text(encoding="utf-8")
        assert text == _schemas.render(schema), f"run scripts/gen_schemas.py ({name})"


def test_schema_show_prints_the_published_bytes(monkeypatch, capsys, room):
    code, out = _tine(monkeypatch, capsys, "schema", "show", "tine-verify-report/2")
    assert code == 0 and out == _schemas.render(_schemas.get("tine-verify-report-2"))
    code, _ = _tine(monkeypatch, capsys, "schema", "show", "no-such")
    assert code == 3  # not found
    code, out = _tine(monkeypatch, capsys, "schema", "show", "tine-run-1", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["definition"] == _schemas.get("tine-run-1")
    assert _schemas.validate_output(payload) == []
    code, _ = _tine(monkeypatch, capsys, "schema", "validate", "missing.json")
    assert code == 3


def test_schema_validate_detects_accepts_and_refuses(monkeypatch, capsys, room):
    _tine(monkeypatch, capsys, "verify", "run.tine", "--offline", "--json")
    good = json.loads(_tine(monkeypatch, capsys, "verify", "run.tine", "--offline", "--json")[1])
    (room / "good.json").write_text(json.dumps(good), encoding="utf-8")
    (room / "bad.json").write_text(json.dumps({**good, "verdict": "maybe"}), encoding="utf-8")
    code, out = _tine(monkeypatch, capsys, "schema", "validate", "good.json", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["ok"] and payload["schema_name"] == "tine-verify-report-2"
    code, out = _tine(monkeypatch, capsys, "schema", "validate", "bad.json", "--json")
    assert code == 4 and not json.loads(out)["ok"]
    assert any("/verdict" in e for e in json.loads(out)["errors"])
    code, _ = _tine(monkeypatch, capsys, "schema", "validate", "run.tine", "--schema", "tine-run-1")
    assert code == 4  # a .tine file is not a run summary object


def test_signed_documents_validate(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _cost_export, _delegation

    key = Ed25519PrivateKey.generate()
    run = Run(id="r", model_info="m", user_prompt="p")
    run.add_step(StepKind.done, {"text": "done"})
    statement = _cost_export.sign_statement(_cost_export.statement(run), key, signer="t")
    assert _schemas.validate(statement) == ("tine-cost-statement-1", [])
    subject = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = _delegation.issue(
        key, subject, agents=["*"], actions=["write"], max_depth=1,
        not_before="2026-01-01T00:00:00Z", not_after="2027-01-01T00:00:00Z",
    )  # fmt: skip
    assert _schemas.validate(cert) == ("opentine-delegation-1", [])
    assert _schemas.validate({**cert, "extra": 1})[1]  # the certificate format is closed
    fleet = {"scheme": "opentine-fleet/1", "fleet_id": "f", "member": "m", "role": "worker",
             "parent": ""}  # fmt: skip
    assert _schemas.validate(fleet) == ("opentine-fleet-1", [])


def test_tlog_receipt_and_checkpoint_validate(tmp_path):
    from opentine.repository import _tlog_note, _tlog_receipt

    root = tmp_path / "log"
    for i in range(3):
        _tlog_note.append(root, "example.com/log", lambda _e, i=i: f"entry {i}".encode())
    receipt = json.loads(json.dumps(_tlog_receipt.make(root, "example.com/log", 1)))
    assert _schemas.validate(receipt) == ("opentine-tlog-receipt-1", [])
    assert _schemas.validate("not a note", "opentine-tlog-checkpoint-1")[1]


def test_line_attribution_record_validates():
    record = {"schema": "opentine-line-attribution/1", "lines_added": 2, "lines_attributed": 1,
              "files": [{"path": "a.py", "ranges": [{
                  "start_line": 1, "end_line": 1, "content_hash": "sha256:00", "run": "r",
                  "step": "s", "seq": 0, "tool": "write", "model": "m"}]}]}  # fmt: skip
    assert _schemas.validate(record) == ("opentine-line-attribution-1", [])
    del record["files"][0]["ranges"][0]["content_hash"]
    assert _schemas.validate(record)[1]


def test_eval_verdict_draft_names_the_coordinated_fields():
    schema = _schemas.get("tine-eval-verdict/1")
    assert {"run", "item", "scorer", "score", "pass"} <= set(schema["required"])
    verdict = {
        "schema": "tine-eval-verdict/1",
        "run": "run:sha256:" + "a" * 64,
        "item": "i1",
        "scorer": {"name": "exact", "kind": "deterministic"},
        "score": 1.0,
        "pass": True,
    }
    assert _schemas.validate(verdict) == ("tine-eval-verdict-1", [])
    assert _schemas.validate({**verdict, "pass": "yes"})[1]


def test_help_json_lists_every_command_and_flag(monkeypatch, capsys, room):
    _code, out = _tine(monkeypatch, capsys, "help", "--json")
    tree = json.loads(out)
    names = {c["name"] for c in tree["commands"]}
    assert set(cli.LEGACY_COMMANDS) | set(cli.REPO_COMMANDS) <= names
    verify = next(c for c in tree["commands"] if c["name"] == "verify")
    assert not verify["advanced"] and any("--offline" in f["flags"] for f in verify["flags"])
    schema = next(c for c in tree["commands"] if c["name"] == "schema")
    assert {s["name"] for s in schema["subcommands"]} == {"list", "show", "validate"}
    _code, out = _tine(monkeypatch, capsys, "help", "schema", "--json")
    assert [c["name"] for c in json.loads(out)["commands"]] == ["schema"]


def test_validator_core_keywords():
    schema = {"type": "object", "required": ["a"], "additionalProperties": False,
              "properties": {"a": {"type": "integer", "minimum": 1}, "b": {"oneOf": [
                  {"type": "string", "pattern": "^x"}, {"type": "null"}]}}}  # fmt: skip
    assert _jsonschema.validate(schema, {"a": 1, "b": "xy"}) == []
    assert _jsonschema.validate(schema, {"a": True})  # a bool is not an integer
    assert _jsonschema.validate(schema, {"a": 0, "c": 1})
    assert _jsonschema.validate(schema, {"a": 2, "b": "y"})
    assert _jsonschema.check_schema({"if": {}}) == ["#: unsupported keyword 'if'"]


def test_help_json_publishes_no_machine_specific_or_env_defaults(monkeypatch, capsys, room):
    monkeypatch.setenv("TINE_SIGNING_KEY", "heads/main-secret-token")
    _code, out = _tine(monkeypatch, capsys, "help", "--json")
    assert str(Path.home()) not in out and str(ROOT) not in out
    assert str(room) not in out and "secret-token" not in out


def test_an_unpublished_tag_is_held_to_the_envelope_not_another_shape():
    document = {"schema": "tine-verify-future/9", "command": "verify", "anything": 1}
    assert _schemas.detect(document) == "tine-cli-envelope-1"
    assert _schemas.validate_output(document) == []


def test_offline_dataset_report_validates(monkeypatch, capsys, room):
    (room / "runs").mkdir()
    shutil.copy(room / "run.tine", room / "runs" / "a.tine")
    _code, out = _tine(monkeypatch, capsys, "verify", "runs", "--offline", "--json")
    document = json.loads(out)
    assert _schemas.detect(document) == "tine-verify-dataset-1"
    assert _schemas.validate_output(document) == []
