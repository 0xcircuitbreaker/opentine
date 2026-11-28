"""0.88 review: base64 blobs inside longer text survive every redacted v3 write.

A signed note or checkpoint is several lines: an origin, a size, a base64 root
and signature lines. When a base64 line ends ``...Pw==`` (or ``...pw=``) and
more text follows, the shape scrubber read everything before the ``=`` as a
credential name and replaced the rest of the note. Fixed values keep the cases
deterministic; each write path is checked on its own.
"""

from __future__ import annotations

import base64

import pytest

from opentine._v3_guards import guarded_redaction
from tests.promote_helpers import key

ROOT = base64.b64encode(bytes(range(15)) + b"?").decode()
SIG = base64.b64encode(bytes(range(15)) + b"\x02\x9c").decode()
NOTE = f"example.org/log\n42\n{ROOT}\n\n— example.org/log {SIG}\n"
INLINE = f"root {ROOT} size 42"


def test_the_values_end_like_a_credential_name():
    assert ROOT.endswith("Pw==") and SIG.endswith("pw=")


@pytest.mark.parametrize("value", [NOTE, INLINE, f"{SIG}\nnext", {"note": NOTE}, [NOTE]])
def test_the_guard_keeps_a_note_with_base64_lines(value):
    assert guarded_redaction({"v": value}, where="t") == {"v": value}


@pytest.mark.parametrize(
    "text",
    ["password= hunter2", "root\nmy password=\nhunter2", "credentials= x",
     "secret_access_key= hunter2", "notes\nAPI_KEY= sk-live-0123456789abcdef"],
)  # fmt: skip
def test_real_assignments_inside_text_are_still_redacted(text):
    out = guarded_redaction({"v": text}, where="t")["v"]
    assert "REDACTED" in out and "hunter2" not in out and "sk-live" not in out


@pytest.fixture
def repo(tmp_path):
    from opentine.repo import Repo

    return Repo.init(tmp_path / "r")


def test_an_attestation_claim_keeps_a_checkpoint_note(repo):
    from opentine import _containment_records as records

    run = records.anchor(repo, "test", "anchor")
    claim = {"convention": "test/1", "checkpoint": NOTE, "inline": INLINE}
    oid = records.record(repo, run, claim, key("5a" * 32), "containment:test")
    row = records.read(repo, oid)
    assert row["signed"] and row["claim"] == claim


def test_an_ingest_record_keeps_a_checkpoint_note_without_verbatim(repo):
    from opentine import _containment_records as records
    from opentine import _ingest_holds

    claim = {"convention": "test/1", "note": NOTE}
    target = records.anchor(repo, "test", "a")
    oid = _ingest_holds.write(repo, target, claim, key("5a" * 32), previous=None,
                              signed_at="2026-11-27T00:00:00Z")  # fmt: skip
    row = _ingest_holds.read(repo, oid, "test/1")
    assert row["signed"] and row["claim"] == claim


def test_a_stored_run_keeps_a_note_in_tool_output(repo):
    from opentine.core import Run, StepKind

    run = Run(user_prompt="p")
    run.add_step(StepKind.tool, {"name": "fetch"}, outputs={"text": NOTE})
    loaded = repo.load_run(repo.put_run(run).run_id)
    assert loaded.steps[0].outputs == {"text": NOTE}


def test_an_annotation_keeps_a_note(repo):
    oid = repo.put("annotation", {"coord": "test", "kind": "k", "value": {"note": NOTE}})
    assert repo.get(oid).payload()["value"] == {"note": NOTE}


@pytest.mark.parametrize(
    "text",
    ["myapplicationdatabase1pw= hunter2", "PrimaryDatabase2Password= hunter2",
     "ProductionDatabaseUser1Password=\nhunter2", "PostgresReplication2Password= hunter2",
     "GITHUBPERSONALACCESSTOKEN= hunter2", "Production2DbPassword= hunter2",
     "AWSProduction2SecretAccessKey= hunter2",
     "env\nPrimaryDatabase2Password= hunter2\nnext"],
)  # fmt: skip
def test_a_long_credential_name_is_not_base64_padding(text):
    # The note exemption once took any long digit-bearing word before "=" for a blob.
    out = guarded_redaction({"v": text}, where="t")["v"]
    assert "REDACTED" in out and "hunter2" not in out
