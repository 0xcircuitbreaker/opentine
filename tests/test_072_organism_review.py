"""0.72 review: holes a loop holding only its optimizer key could use."""

from __future__ import annotations

import pytest

from opentine import _organism, _organism_gate
from opentine.repository._holds import edit_holds, holds_path
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_072_organism import ART, _claude, _hook, _key, repo  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
NAME = "ckpt/sleeper.safetensors"


def _blocked(body: dict) -> bool:
    return body.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_dropping_the_tag_hold_rows_does_not_untag(repo):  # noqa: F811
    _organism.tag(repo, ART, _key("policy"), names=[NAME], reason="r")
    keep = lambda rows: [r for r in rows if not r["target"].startswith("organism:")]  # noqa: E731
    edit_holds(holds_path(repo), keep)
    assert _organism.tagged(repo, ART)["tagged"]
    assert _blocked(_hook(repo, _claude("s1", NAME)))


def test_deleting_the_holds_file_does_not_untag(repo):  # noqa: F811
    _organism.tag(repo, ART, _key("policy"), names=[NAME], reason="r")
    holds_path(repo).unlink()
    assert _blocked(_hook(repo, _claude("s1", NAME)))


def test_a_run_claimed_in_the_hook_payload_does_not_pick_the_approval(repo):  # noqa: F811
    _organism.tag(repo, ART, _key("policy"), names=[NAME], reason="r")
    _organism.approve(repo, ART, "approved-run", _key("a1"), why="study")
    payload = {**_claude("loop-session", NAME), "run": "approved-run"}
    assert _blocked(_hook(repo, payload))


def test_a_tagged_path_also_matches_by_its_file_name(repo, tmp_path):  # noqa: F811
    _organism.tag(repo, ART, _key("policy"), names=["/abs/deep/sleeper.bin"], reason="r")
    call = {"name": "Bash", "arguments": {"command": "cd /abs/deep && python l.py sleeper.bin"}}
    assert _organism_gate.decide(repo, call, "r1")["outcome"] == "block"
