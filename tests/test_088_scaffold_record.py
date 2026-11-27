"""0.88: the signed scaffold glob list, the held per-run record and the CLI."""

from __future__ import annotations

import json
import sys

import pytest

from opentine._scaffold_files import PIN, ScaffoldError, globs, pin, pinned
from opentine._scaffold_manifest import build
from tests.promote_helpers import fingerprint, key, write_key
from tests.regions_helpers import AT, POLICY, policy_role

OPTIMIZER = "9e" * 32


@pytest.fixture
def root(tmp_path, monkeypatch):
    from tests.key_roles_helpers import pin_roles

    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    monkeypatch.delenv("OPENTINE_TRUST_OWNER", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_BUNDLE", raising=False)
    base = tmp_path / "repo"
    (base / ".tine").mkdir(parents=True)
    roles = f'version = 1\n[roles]\n{policy_role()}optimizer = ["{fingerprint(OPTIMIZER)}"]\n'
    (base / ".tine" / "key-roles.toml").write_bytes(roles.encode())
    pin_roles(base / ".tine")
    for rel in ("CLAUDE.md", "prompts/system.md", ".claude/skills/s/SKILL.md"):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_bytes(f"{rel}\n".encode())
    return base


def test_a_signed_list_replaces_the_defaults(root):
    pin(root, {"claude-code": ["CLAUDE.md", "prompts/**"]}, key(POLICY), AT)
    manifest = build("claude-code", root)
    assert manifest["source"] == "pinned" and manifest["globs"] == ["CLAUDE.md", "prompts/**"]
    assert [r["path"] for r in manifest["files"]] == ["CLAUDE.md", "prompts/system.md"]
    with pytest.raises(ScaffoldError, match="names no 'codex'"):
        globs("codex", root)  # a filed list never falls back to the defaults


def test_only_a_pinned_non_optimizer_policy_key_may_sign_the_list(root):
    for seed in (OPTIMIZER, "77" * 32):
        with pytest.raises(ScaffoldError, match="scaffold.files-unpinned"):
            pin(root, {"claude-code": ["CLAUDE.md"]}, key(seed), AT)
    assert not (root / PIN).exists()


@pytest.mark.parametrize("edit", ["tamper", "garbage", "optimizer-signed"])
def test_a_filed_list_that_fails_is_refused_not_ignored(root, edit):
    from opentine._integrity_run import _dump, _sign

    pin(root, {"claude-code": ["CLAUDE.md"]}, key(POLICY), AT)
    path = root / PIN
    if edit == "tamper":
        doc = json.loads(path.read_bytes())
        doc["claim"]["harnesses"]["claude-code"] = ["nothing/**"]
        path.write_bytes(json.dumps(doc).encode())
    elif edit == "garbage":
        path.write_bytes(b"[[[")
    else:
        claim = {"schema": "opentine.scaffold-files/1", "harnesses": {"claude-code": ["x"]}}
        _dump(path, _sign(key(OPTIMIZER), claim, "sha256:" + "0" * 64, AT))
    with pytest.raises(ScaffoldError, match="scaffold.files-unpinned"):
        pinned(root)
    with pytest.raises(ScaffoldError):
        build("claude-code", root)


def test_a_glob_that_climbs_out_is_refused(root):
    with pytest.raises(ScaffoldError, match="climbs out"):
        pin(root, {"claude-code": ["../elsewhere/**"]}, key(POLICY), AT)


def _repo_and_run(tmp_path):
    from opentine import _containment_records as records
    from opentine.repo import Repo

    repo = Repo.init(tmp_path / "store")
    return repo, records.anchor(repo, "test", "a run")


def test_the_manifest_is_signed_onto_the_run_and_held(root, tmp_path):
    from opentine._scaffold_record import record, recorded
    from opentine.repository._holds import HoldError, release

    repo, run = _repo_and_run(tmp_path)
    manifest = build("claude-code", root)
    oid = record(repo, run, manifest, key("5a" * 32))
    [row] = recorded(repo, run)
    assert row["oid"] == oid and row["signed"] and row["tree_ok"]
    assert row["signer"] == fingerprint("5a" * 32)  # the key that signed, nothing claimed
    assert row["claim"]["files"] == manifest["files"] and row["claim"]["run"] == run
    with pytest.raises(HoldError, match="scaffold manifest"):
        release(repo, f"scaffold-manifest:{run}")


def test_a_credential_shaped_path_is_refused_not_stored_altered(root, tmp_path):
    from opentine._scaffold_record import record, recorded

    repo, run = _repo_and_run(tmp_path)
    (root / ".claude/skills/api_key=sk-live-abcdef0123456789").mkdir(parents=True)
    (root / ".claude/skills/api_key=sk-live-abcdef0123456789/SKILL.md").write_bytes(b"x\n")
    with pytest.raises(ScaffoldError, match="scaffold.redaction"):
        record(repo, run, build("claude-code", root), key("5a" * 32))
    assert recorded(repo, run) == []


def _tine(monkeypatch, capsys, *argv):
    from opentine import cli

    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_scaffold_record_diff_and_pin(root, tmp_path, monkeypatch, capsys):
    repo, run = _repo_and_run(tmp_path)
    signer = write_key(tmp_path / "k.key", "5a" * 32)
    code, out, _ = _tine(monkeypatch, capsys, "agent", "scaffold", "--root", str(root),
                         "--record", run, "--key", str(signer), "--repo", str(repo.path),
                         "--json")  # fmt: skip
    assert code == 0
    first = json.loads(out)
    assert first["command"] == "agent scaffold" and first["record"]
    (tmp_path / "a.json").write_bytes(out.encode())
    (root / ".claude/skills/s/SKILL.md").write_bytes(b"edited\n")
    _code, out, _ = _tine(monkeypatch, capsys, "agent", "scaffold", "--root", str(root), "--json")
    (tmp_path / "b.json").write_bytes(out.encode())
    code, out, _ = _tine(monkeypatch, capsys, "agent", "scaffold-diff", str(tmp_path / "a.json"),
                         str(tmp_path / "b.json"), "--json")  # fmt: skip
    found = json.loads(out)
    assert code == 0 and [r["path"] for r in found["changed"]] == [".claude/skills/s/SKILL.md"]
    forged = json.loads((tmp_path / "b.json").read_bytes())
    forged["manifest"]["files"][0]["sha256"] = "0" * 64  # tree digest no longer matches
    (tmp_path / "c.json").write_bytes(json.dumps(forged).encode())
    code, _, err = _tine(monkeypatch, capsys, "agent", "scaffold-diff", str(tmp_path / "a.json"),
                         str(tmp_path / "c.json"))  # fmt: skip
    assert code == 2 and "tree_sha256 does not match" in err
    policy = write_key(tmp_path / "p.key", POLICY)
    code, out, _ = _tine(monkeypatch, capsys, "agent", "scaffold-pin", "--harness", "claude-code",
                         "--glob", "CLAUDE.md", "--key", str(policy), "--root", str(root),
                         "--at", AT, "--json")  # fmt: skip
    assert code == 0 and json.loads(out)["harnesses"] == {"claude-code": ["CLAUDE.md"]}
    code, _, err = _tine(monkeypatch, capsys, "agent", "scaffold", "--root", str(root),
                         "--harness", "codex")  # fmt: skip
    assert code == 1 and "scaffold.files-unpinned" in err
