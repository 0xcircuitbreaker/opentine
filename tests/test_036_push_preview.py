"""0.36 ``tine push --dry-run`` / ``--outgoing``, the signed push manifest, and
``tine.transcriptRemote`` routing runs off the code remote."""

from __future__ import annotations

import json
import shutil
import socket

import pytest

from opentine import _push_preview, cli
from opentine._signing_keys import hmac_key_from_file
from opentine.graph import Run, StepKind
from opentine.kernel import canonical_json
from opentine.policies import PolicySet
from opentine.repository import Repo

HMAC_KEY = "ab" * 32
POLICIES = PolicySet().to_dict()


def _run(run_id: str) -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="p", policies=POLICIES)
    run.add_step(StepKind.done, {"text": run_id})
    return run


@pytest.fixture
def repo(tmp_path):
    store = Repo.init(tmp_path / "store")
    store.put_run(_run("first"), ref="heads/main")
    return store


@pytest.fixture
def offline(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("dry run touched the network")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def _dry_run(capsys, repo, *extra: str) -> dict:
    url = "https://tine.example.invalid/v1"
    cli.main(["push", url, "--repo", str(repo.path), "--dry-run", *extra])
    return json.loads(capsys.readouterr().out)


def test_dry_run_lists_refs_objects_and_runs_without_network(repo, capsys, offline):
    body = _dry_run(capsys, repo)
    new = repo.read_ref("heads/main")
    assert body["refs"] == [
        {"ref": "heads/main", "old": None, "new": new, "objects": body["objects"]["count"]}
    ]
    kinds = body["objects"]["by_kind"]
    assert kinds["run"]["count"] == 1 and kinds["run"]["bytes"] > 0
    assert body["objects"]["bytes"] == sum(k["bytes"] for k in kinds.values())
    assert body["runs"] == [{"run": new, "redaction_ruleset": "opentine-redaction/2"}]
    assert "signature" not in body


def test_outgoing_counts_only_what_the_tracking_ref_lacks(repo, capsys, offline):
    old = repo.read_ref("heads/main")
    repo.update_ref("remotes/origin/main", old, expected_old=None)
    assert _dry_run(capsys, repo, "--outgoing")["objects"]["count"] == 0
    repo.put_run(_run("second"), ref="heads/main")
    body = _dry_run(capsys, repo, "--outgoing")
    assert body["refs"][0]["old"] == old
    assert [run["run"] for run in body["runs"]] == [repo.read_ref("heads/main")]


def test_signed_manifest_is_canonical_and_verifies(repo, capsys, offline, tmp_path):
    key = tmp_path / "k.hex"
    key.write_text(HMAC_KEY)
    out = tmp_path / "push.manifest.json"
    _dry_run(capsys, repo, "--manifest", str(out), "--key-file", str(key), "--key-id", "me")
    raw = out.read_bytes()
    manifest = json.loads(raw)
    assert raw == canonical_json(manifest)
    assert manifest["signature"]["scheme"] == "tine-sig/3"
    assert _push_preview.verify(manifest, hmac_key=hmac_key_from_file(key)).ok
    manifest["refs"][0]["new"] = "run:sha256:" + "0" * 64
    assert not _push_preview.verify(manifest, hmac_key=hmac_key_from_file(key)).ok


def test_key_flag_without_a_manifest_is_refused(repo, tmp_path):
    key = tmp_path / "k.hex"
    key.write_text(HMAC_KEY)
    with pytest.raises(SystemExit):
        cli.main(["push", "https://x.invalid", "--repo", str(repo.path), "--key-file", str(key)])


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_transcript_remote_routes_runs_to_another_remote(tmp_path, monkeypatch):
    import subprocess

    from opentine._git_push_sync import transcript_remote

    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("HOME", str(tmp_path))
    root = tmp_path / "proj"
    root.mkdir()

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    git("init", "-q")
    git("remote", "add", "transcripts", str(tmp_path / "t.git"))
    assert transcript_remote(root, "/code") == "/code"
    git("config", "tine.transcriptRemote", "transcripts")
    assert transcript_remote(root, "/code") == str(tmp_path / "t.git")
    git("config", "tine.transcriptRemote", str(tmp_path / "elsewhere"))
    assert transcript_remote(root, "/code") == str(tmp_path / "elsewhere")


def test_manifest_remote_drops_userinfo_and_key_id_needs_a_key():
    import argparse

    import pytest

    from opentine import _cli_push_preview, _push_preview

    assert _push_preview.public_remote("https://u:secret@host:8/a/b@c") == "https://host:8/a/b@c"
    assert _push_preview.public_remote("/local/path") == "/local/path"
    args = argparse.Namespace(dry_run=True, manifest=None, key_id="k1")
    with pytest.raises(ValueError, match="key-id"):
        _cli_push_preview.wants_manifest(args)
