"""0.13 F4: opentine-agent/1 identities and signed tine-actions/1 manifests."""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _agent_identity as identity
from opentine._actions import ACTIONS_SCHEMA
from opentine._actions_db import ActionIndex
from opentine._actions_manifest import build_body, sign
from opentine._actions_verdict import load_manifest, manifest_path, save_manifest, verify
from opentine._agent_definition import DefinitionError, definition_digest
from opentine._agent_trust import lineage_refs
from opentine.graph import Run, StepKind
from opentine.signing import generate_ed25519

HMAC = b"k" * 32


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    for name in ("OPENTINE_AGENT_KEY", "OPENTINE_AGENT_PARENT", "OPENTINE_AGENT_PARENT_RUN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    runs = tmp_path / ".tine_runs"
    runs.mkdir()
    monkeypatch.setattr(cli, "RUNS_DIR", runs)
    return runs


def _record(**extra) -> dict:
    return identity.build(harness="claude-code", model="claude-opus-5-5", **extra)


def _run(run_id: str, record: dict | None = None, *, command: str = "ls", spawn=False) -> Run:
    metadata = {"harness": "claude-code"}
    if record is not None:
        metadata["agent_identity"] = record
    run = Run(run_id=run_id, model_info="claude-opus-5-5", metadata=metadata)
    run.add_step(StepKind.tool, {"name": "Bash", "arguments": {"command": command}})
    if spawn:
        run.add_step(StepKind.tool, {"name": "Task", "arguments": {"prompt": "review"}})
    return run


def _json(capsys, *argv: str) -> dict:
    cli.main([*argv, "--json"])
    return json.loads(capsys.readouterr().out)


def _exit(*argv: str) -> int:
    with pytest.raises(SystemExit) as caught:
        cli.main(list(argv))
    return caught.value.code


# --- the identity record ------------------------------------------------------ #


def test_ref_is_stable_and_ignores_instance_and_lineage():
    one = _record(instance="a" * 32)
    two = _record(instance="b" * 32, parent="agt_" + "c" * 32)
    assert identity.agent_ref(one) == identity.agent_ref(two)
    assert identity.REF_RE.fullmatch(identity.agent_ref(one))
    assert identity.agent_ref(_record(key_fpr="sha256:" + "0" * 64)) != identity.agent_ref(one)


def test_unicode_lookalike_names_are_normalised_and_flagged():
    fullwidth = identity.build(harness="ｃｌａｕｄｅ-code", model="claude-opus-5-5")
    assert identity.agent_ref(fullwidth) == identity.agent_ref(_record())
    cyrillic = identity.build(harness="clаude-code", model="claude-opus-5-5")  # U+0430
    assert identity.agent_ref(cyrillic) != identity.agent_ref(_record())
    assert identity.lookalike("clаude-code") and not identity.lookalike("claude-code")
    with pytest.raises(identity.IdentityError):
        identity.validate({**_record(), "harness": "ｃlaude"})  # not normalised


def test_prefixes_are_never_refs():
    ref = identity.agent_ref(_record())
    assert identity.check_query_ref(ref) == ref
    for short in (ref[:12], ref[:-1], ref.upper()):
        with pytest.raises(identity.IdentityError):
            identity.check_query_ref(short)
    assert not identity.same_ref(ref, ref[:-1]) and identity.same_ref(ref, ref)


def test_malformed_lineage_fields_are_refused():
    with pytest.raises(identity.IdentityError):
        _record(parent="agt_1234")
    bad = {**_record(), "parent": "agt_" + "z" * 32}
    run = _run("r", None)
    run.metadata["agent_identity"] = bad
    assert identity.run_identity(run) is None
    assert identity.run_agent_ref(run) == "legacy:claude-code"


def test_definition_digest_hashes_files_never_stores_them(tmp_path):
    (tmp_path / "CLAUDE.md").write_bytes(b"line one\r\nsecret sk-test\r\n")
    crlf = definition_digest(["CLAUDE.md"], tmp_path)
    (tmp_path / "CLAUDE.md").write_bytes(b"line one\nsecret sk-test\n")
    assert definition_digest(["CLAUDE.md"], tmp_path) == crlf
    assert "sk-test" not in json.dumps(_record(definition_digest=crlf))
    for escape in ("../x", str(tmp_path.parent / "x")):
        with pytest.raises(DefinitionError):
            definition_digest([escape], tmp_path)


def test_definition_symlink_is_refused(tmp_path):
    (tmp_path / "real.md").write_text("x")
    try:
        (tmp_path / "CLAUDE.md").symlink_to(tmp_path / "real.md")
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(DefinitionError):
        definition_digest(["CLAUDE.md"], tmp_path)


# --- tine-actions/1 ------------------------------------------------------------ #


def test_hmac_manifest_round_trip_and_states(tmp_path):
    run = _run("run-a", _record())
    manifest = sign(run, HMAC, algorithm="hmac-sha256")
    assert verify(None, run).state == "unsigned"
    assert verify({"body": manifest["body"]}, run).state == "unsigned"
    assert verify(manifest, run).state == "unknown-key"
    assert verify(manifest, run, hmac_key=HMAC).state == "verified"
    assert verify(manifest, run, hmac_key=b"x" * 32).state == "mismatch"


def test_edit_or_truncation_is_a_mismatch():
    run = _run("run-a", _record(), spawn=True)
    manifest = sign(run, HMAC, algorithm="hmac-sha256")
    run.steps[0].inputs["arguments"]["command"] = "rm -rf /"
    assert verify(manifest, run, hmac_key=HMAC).state == "mismatch"
    run = _run("run-a", _record(), spawn=True)
    cut = json.loads(json.dumps(manifest))
    cut["body"]["entries"].pop()
    assert verify(cut, run, hmac_key=HMAC).state == "mismatch"


def test_manifest_replayed_onto_another_run_fails(home):
    first, second = _run("run-a", _record()), _run("run-b", _record())
    manifest = sign(first, HMAC, algorithm="hmac-sha256")
    assert verify(manifest, second, hmac_key=HMAC).state == "mismatch"
    save_manifest(home / "manifests", manifest)
    shutil.copy(
        manifest_path(home / "manifests", "run-a"), manifest_path(home / "manifests", "run-b")
    )
    moved = load_manifest(home / "manifests", "run-b")
    assert verify(moved, second, hmac_key=HMAC).state == "mismatch"


def test_identity_key_binding(home):
    seed, public = generate_ed25519()
    other_seed, _ = generate_ed25519()
    from opentine._signing_pins import key_fingerprint

    fpr = key_fingerprint(bytes.fromhex(public))
    run = _run("run-a", _record(key_fpr=fpr))
    good = sign(run, seed, algorithm="ed25519")
    assert verify(good, run).state == "unknown-key"
    assert verify(good, run, pins=frozenset({fpr})).state == "verified"
    wrong = sign(run, other_seed, algorithm="ed25519")
    assert verify(wrong, run, pins=frozenset({fpr})).state == "mismatch"


# --- CLI ---------------------------------------------------------------------- #


def test_keygen_agent_sign_verify_and_audit(home, capsys):
    run = _run("run-a", _record())
    run.save(home / "run-a.tine")
    _run("run-old").save(home / "run-old.tine")  # a pre-0.13 run: no identity
    cli.main(["keygen", "--agent", "coder"])
    keys = home.parent / "xdg" / "opentine" / "agent-keys"
    assert (keys / "coder.key").exists() and (keys / "coder.pub").exists()
    assert not (home.parent / "xdg" / "opentine" / "release").exists()
    assert _exit("actions", "run-a", "--verify") == 1
    cli.main(["actions", "run-a", "--sign", "--agent", "coder"])
    capsys.readouterr()
    assert _json(capsys, "actions", "run-a")["trust"] == "verified"  # own key
    cli.main(["actions", "run-a", "--verify"])  # exit 0
    policy = home.parent / "p.toml"
    policy.write_text('[[rule]]\nid = "no-push"\nprogram = "git"\n')
    assert _exit("audit", "--policy", str(policy), "--require-signed") == 1
    out = capsys.readouterr().out
    assert "run-old" in out and "verified" in out
    (home / "run-old.tine").unlink()
    cli.main(["audit", "--policy", str(policy), "--require-signed"])


def test_who_shows_trust_and_filters_by_ref(home, capsys):
    record = _record()
    _run("run-a", record).save(home / "run-a.tine")
    _run("run-old").save(home / "run-old.tine")
    ref = identity.agent_ref(record)
    rows = _json(capsys, "who", "--list", "--agent-ref", ref)["actions"]
    assert [row["run_id"] for row in rows] == ["run-a"]
    assert rows[0]["trust"] == "unsigned" and rows[0]["agent_ref"] == ref
    legacy = _json(capsys, "who", "--list", "--agent-ref", "legacy:claude-code")["actions"]
    assert [row["run_id"] for row in legacy] == ["run-old"]
    groups = _json(capsys, "who", "--by", "agent_ref")["groups"]
    assert {group["trust"] for group in groups} == {"unsigned"}
    assert _exit("who", "--agent-ref", ref[:10]) == 2
    assert "not a full agent ref" in capsys.readouterr().out
    assert _json(capsys, "who", "--list", "--verified-only")["actions"] == []


def test_forged_verified_rows_in_sqlite_are_ignored(home, capsys):
    record = _record()
    _run("run-a", record).save(home / "run-a.tine")
    _json(capsys, "who")  # build the keyed index
    db = sqlite3.connect(home / "actions.sqlite")
    with db:
        db.execute("ALTER TABLE actions ADD COLUMN verified INTEGER DEFAULT 1")
        db.execute("UPDATE actions SET agent_ref = ?", ("agt_" + "f" * 32,))
    db.close()
    assert _json(capsys, "who", "--list", "--verified-only")["actions"] == []
    forged = _json(capsys, "who", "--list", "--agent-ref", "agt_" + "f" * 32)["actions"]
    assert forged == []  # the run, reloaded, does not hold that ref


def test_lineage_needs_both_sides(home, capsys):
    parent = _run("run-p", _record(), spawn=True)
    parent_ref = identity.agent_ref(_record())
    spawn = build_body(parent)["spawns"]
    assert spawn
    child_record = identity.build(
        harness="claude-code",
        model="claude-haiku",
        parent=parent_ref,
        parent_run="run-p",
        spawn_step=spawn[0],
    )
    forged_record = identity.build(
        harness="claude-code", model="evil", parent=parent_ref, parent_run="run-p", spawn_step="x"
    )
    for run in (parent, _run("run-c", child_record), _run("run-f", forged_record)):
        run.save(home / f"{run.id}.tine")
        cli.main(["actions", run.id, "--sign", "--key-file", str(_key(home))])
    capsys.readouterr()
    claimed = _json(capsys, "who", "--list", "--lineage", parent_ref)["actions"]
    assert {row["run_id"] for row in claimed} == {"run-p", "run-c", "run-f"}
    # HMAC-signed manifests verify only with the key, which who does not take:
    assert {row["trust"] for row in claimed} == {"unknown-key"}


def _key(home):
    path = home.parent / "hmac.key"
    path.write_text("ab" * 32 + "\n")
    return path


def test_lineage_walk_is_iterative_and_checks_links():
    root = "agt_" + "0" * 32
    edges = [(f"r{i}", f"agt_{i + 1:032x}", f"agt_{i:032x}") for i in range(3000)]
    edges.append(("loop", root, f"agt_{3000:032x}"))
    assert len(lineage_refs(root, edges)) == 3001

    class Refuse:
        def lineage_ok(self, run_id):
            return run_id != "r1"

    assert len(lineage_refs(root, edges, resolver=Refuse())) == 2


def test_lineage_verified_only_with_ed25519(home, capsys):
    cli.main(["keygen", "--agent", "lead"])
    parent = _run("run-p", _record(), spawn=True)
    ref = identity.agent_ref(_record())
    step = build_body(parent)["spawns"][0]
    kid = identity.build(
        harness="claude-code", model="m", parent=ref, parent_run="run-p", spawn_step=step
    )
    fake = identity.build(
        harness="claude-code", model="f", parent=ref, parent_run="run-p", spawn_step="nope"
    )
    for run in (parent, _run("run-c", kid), _run("run-f", fake)):
        run.save(home / f"{run.id}.tine")
        cli.main(["actions", run.id, "--sign", "--agent", "lead"])
    capsys.readouterr()
    rows = _json(capsys, "who", "--list", "--lineage", ref, "--verified-only")["actions"]
    assert {row["run_id"] for row in rows} == {"run-p", "run-c"}
    shown = _json(capsys, "agent", "show", "run-f")
    assert shown["trust"] == "verified" and shown["lineage_verified"] is False
    assert _json(capsys, "agent", "show", "run-c")["lineage_verified"] is True


def test_hostile_agent_strings_are_escaped(home, capsys):
    hostile = "\x1b]0;pwn\x07[bold red]evil[/]"
    run = Run(run_id="run-h", model_info="m", metadata={"harness": hostile})
    run.add_step(StepKind.tool, {"name": "Bash", "arguments": {"command": "ls"}})
    run.save(home / "run-h.tine")
    cli.main(["who", "--list"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    cli.main(["agent", "show", "run-h"])
    assert "\x1b" not in capsys.readouterr().out


def test_agents_toml_is_inert_until_trusted(home, capsys):
    seed, public = generate_ed25519()
    from opentine._signing_pins import key_fingerprint

    fpr = key_fingerprint(bytes.fromhex(public))
    run = _run("run-a", _record())
    run.save(home / "run-a.tine")
    save_manifest(home / "manifests", sign(run, seed, algorithm="ed25519"))
    (home.parent / ".tine").mkdir()
    pins = home.parent / ".tine" / "agents.toml"
    pins.write_text(f'[agents.coder]\nkeys = ["{fpr}"]\n')
    assert _json(capsys, "actions", "run-a")["trust"] == "unknown-key"
    cli.main(["agent", "trust"])
    capsys.readouterr()
    assert _json(capsys, "actions", "run-a")["trust"] == "verified"
    pins.write_text(f'[agents.coder]\nkeys = ["{fpr}"]\n# edited\n')
    assert _json(capsys, "actions", "run-a")["trust"] == "unknown-key"


def test_agent_id_cli(home, capsys, tmp_path):
    (tmp_path / "CLAUDE.md").write_text("be careful")
    shown = _json(capsys, "agent", "id", "--harness", "claude-code", "--model", "m")
    assert shown["files"] == ["CLAUDE.md"]
    assert shown["identity"]["definition_digest"].startswith("sha256:")
    assert "be careful" not in json.dumps(shown)


def test_schema_4_index_rebuilds_an_old_one(home, capsys):
    _run("run-a", _record()).save(home / "run-a.tine")
    _json(capsys, "who")
    db = sqlite3.connect(home / "actions.sqlite")
    stamp = db.execute("SELECT value FROM meta WHERE key='stamp'").fetchone()[0]
    assert stamp.startswith(f"{ACTIONS_SCHEMA}:") and ACTIONS_SCHEMA == 4
    with db:
        db.execute("UPDATE meta SET value = '3:0.12.1:x' WHERE key = 'stamp'")
    db.close()
    with ActionIndex(home / "actions.sqlite") as index:
        assert index.count() == 0  # discarded, not trusted
    rows = _json(capsys, "who", "--list")["actions"]
    assert rows[0]["agent_ref"].startswith("agt_")


def test_harness_capture_records_identity(home):
    from opentine.harnesses._wrapper import OpentineHarness

    class Stub:
        name = "claude-code"
        model_info = "claude-opus-5-5"

        async def execute(self, task, context=None, step_callback=None):
            return {"ok": True}

    run = OpentineHarness(Stub()).run_sync("task")
    record = identity.run_identity(run)
    assert record["harness"] == "claude-code" and len(record["instance"]) == 32
    assert identity.run_agent_ref(run) == identity.agent_ref(_record())


# --- backwards compatibility --------------------------------------------------- #

COMPAT = sorted(
    (Path(__file__).parent / "fixtures" / "compat").glob("v0_*/*.tine"), key=lambda p: str(p)
)


@pytest.mark.parametrize("path", COMPAT, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_old_artifacts_are_legacy_and_unsigned(path):
    run = Run.load(path)
    assert identity.run_identity(run) is None
    assert identity.run_agent_ref(run).startswith("legacy:")
    assert verify(None, run).state == "unsigned"
    body = build_body(run)  # a pre-0.13 run can still be signed now
    assert body["identity"] is None and body["run_id"] == run.id


@pytest.mark.parametrize(
    "repo_dir",
    sorted((Path(__file__).parent / "fixtures" / "compat").glob("v0_*/repo")),
    ids=lambda p: p.parent.name,
)
def test_old_repositories_answer_who_with_trust_states(repo_dir, home, capsys):
    work = home.parent / "repo"
    shutil.copytree(repo_dir, work)
    shown = _json(capsys, "who", "--list", "--repo", str(work))
    for row in shown["actions"]:
        assert row["trust"] == "unsigned" and row["agent_ref"].startswith("legacy:")


def test_a_claimed_parent_run_is_never_read_as_a_path(home, capsys):
    outside = home.parent / "elsewhere.tine"
    _run(str(outside), _record(), spawn=True).save(outside)
    child = identity.build(
        harness="claude-code",
        model="m",
        parent=identity.agent_ref(_record()),
        parent_run=str(outside),
        spawn_step="s",
    )
    _run("run-c", child).save(home / "run-c.tine")
    shown = _json(capsys, "agent", "show", "run-c")
    assert shown["lineage_verified"] is False
    import argparse

    from opentine._cli_who_trust import resolver

    assert resolver(argparse.Namespace(repo=None)).run(str(outside)) is None
