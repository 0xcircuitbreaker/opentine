"""0.56: the Entire fixture refreshed against entireio/cli v0.13.3.

v0.13.3 writes the same checkpoint subtree under both backends: the legacy
``entire/checkpoints/v1`` branch (at ``<id[:2]>/<id[2:]>/``) and the per-checkpoint
``refs/entire/checkpoints/<id[-2:]>/<id>`` refs (at the tree root). New in the
subtree since the 0.42 fixture: a compact ``transcript.jsonl`` (the Entire
Transcript Format, ``sessions[].compact_transcript``) and the session's
``compact_transcript_start``. The importer must keep reading the raw
``full.jsonl``, and the two backends must import to the same events.
"""

from __future__ import annotations

import json
import shutil

import pytest

from opentine.trace import _entire_git
from opentine.trace._import_entire import entire_events
from tests.test_entire_refs_0_42 import (
    ULID,
    _add_ref_checkpoint,
    _commit_tree,
    _fixture_files,
    _init,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _shape(events):
    return [(e.kind, e.model, e.usage, e.inputs, e.outputs) for e in events]


def test_fixture_carries_the_v0_13_3_fields():
    files = _fixture_files()
    summary = json.loads(files["metadata.json"])
    session = json.loads(files["0/metadata.json"])
    assert summary["cli_version"] == session["cli_version"] == "0.13.3"
    assert summary["sessions"][0]["compact_transcript"] == "/0/transcript.jsonl"
    assert session["compact_transcript_start"] == 0
    first = json.loads(files["0/transcript.jsonl"].splitlines()[0])
    assert first["v"] == 1 and first["agent"] == "claude-code"


def test_raw_transcript_is_read_not_the_compact_one(tmp_path):
    root = _init(tmp_path / "proj")
    _add_ref_checkpoint(root)
    events = entire_events(str(root))
    assert [e.kind for e in events] == ["human", "model", "tool"]  # full.jsonl has the tool call
    assert events[0].attributes["entire"]["layout"] == "refs"


def test_branch_and_ref_backends_import_the_same_checkpoint(tmp_path):
    by_ref = _init(tmp_path / "refs")
    _add_ref_checkpoint(by_ref)
    by_branch = _init(tmp_path / "branch")
    prefix = f"{ULID[:2]}/{ULID[2:]}/"
    files = _fixture_files(prefix)
    summary = json.loads(files[prefix + "metadata.json"])
    for session in summary["sessions"]:  # branch paths are absolute from the branch root
        for key, value in list(session.items()):
            session[key] = f"/{prefix.rstrip('/')}{value}"
    files[prefix + "metadata.json"] = json.dumps(summary).encode()
    _commit_tree(by_branch, files, _entire_git.BRANCH)
    from_ref, from_branch = entire_events(str(by_ref)), entire_events(str(by_branch))
    assert from_branch[0].attributes["entire"]["layout"] == "branch"
    assert _shape(from_branch) == _shape(from_ref)
