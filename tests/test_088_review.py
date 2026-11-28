"""0.88 review: edits built to slip past the structural diff, skill labels and redaction.

Each test plants one evasion: a tree hidden in a cache or VCS-looking folder, a
Python coding cookie that turns a comment into code, a dotted key that aliases a
nested one, a forged ``bound`` in a signed diff, two signed lineage records that
name different skills for one run, and a base64 token inside a note.
"""

from __future__ import annotations

import json

import pytest

from opentine._lineage import record
from opentine._promote_skill import findings
from opentine._sdiff import check, compute, dumps, sign
from tests.promote_helpers import AT, PROMOTER, RUN_A, RUN_B, key
from tests.test_088_structural_diff import BASE, files, pair, tree

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

SKILL_A, SKILL_B = "sha256:" + "a1" * 32, "sha256:" + "b2" * 32


@pytest.mark.parametrize(
    "folder", ["__pycache__", "." + "git", "skills/." + "git"]
)  # a planted folder
def test_a_file_in_a_skipped_looking_folder_is_still_listed(tmp_path, folder):
    old, new = pair(tmp_path)
    tree(new, {f"{folder}/hooks/pre-commit": "rm -rf ~\n"})
    claim = compute(old, new)
    assert f"{folder}/hooks/pre-commit" in files(claim)


def test_a_coding_cookie_cannot_turn_a_comment_into_hidden_code(tmp_path):
    edited = "# coding: utf-7\n" + BASE["agent.py"] + "# +AAo-import os\n"
    old, new = pair(tmp_path, agent_DOT_py=edited)
    row = files(compute(old, new))["agent.py"]
    assert row["structural"], row


@pytest.mark.parametrize(
    ("before", "after"),
    [({"a": {"b": 1}}, {"a.b": 1}), ({"x": [1]}, {"x[0]": 1}), ({"k": {"1": 1}}, {"k": {"1": 1}})],
)
def test_a_dotted_key_does_not_alias_a_nested_one(tmp_path, before, after):
    old, new = pair(tmp_path, settings_DOT_json=json.dumps(before))
    tree(old, {"settings.json": json.dumps(before)})
    tree(new, {"settings.json": json.dumps(after) + ("\n" if before == after else "")})
    row = files(compute(old, new))["settings.json"]
    assert row["structural"] is (before != after), row


def test_a_check_recomputes_bound_from_the_lineage(tmp_path):
    old, new = pair(tmp_path, agent_DOT_py=BASE["agent.py"].replace("3", "4"))
    lineage = tmp_path / "lineage"
    variant = record(key(PROMOTER), run=RUN_B, artifacts={"skill": SKILL_B}, store=lineage,
                     at=AT)["variant"]  # fmt: skip
    claim = compute(old, new, to_variant=variant, to_artifacts={"skill": SKILL_B})
    assert claim["to"]["bound"] is False
    claim["to"]["bound"] = True  # the signer claims its tree is the recorded one
    path = tmp_path / "diff.json"
    path.write_bytes(dumps(sign(claim, key(PROMOTER), at=AT)))
    out = check(path, old, new, to_artifacts={"skill": SKILL_B})
    assert [f["code"] for f in out["findings"]] == ["lineage-diff.mismatch"]


@pytest.mark.parametrize("trees", [("c", "d"), ("d", "c")])
def test_two_records_naming_different_skills_for_one_run_are_a_change(tmp_path, trees):
    record(key(PROMOTER), run=RUN_A, artifacts={"skill": SKILL_A}, store=tmp_path, at=AT)
    for skill, mark in zip((SKILL_A, SKILL_B), trees):  # file name order must not decide
        artifacts = {"skill": skill, "code_tree": "sha256:" + mark * 64}
        record(key(PROMOTER), run=RUN_B, artifacts=artifacts, store=tmp_path, at=AT)
    refused, _, row = findings({"skill_labels": "required"}, candidate=RUN_B, current=RUN_A,
                               label="prod", lineage=tmp_path, repo_path=None)  # fmt: skip
    assert [r["code"] for r in refused] == ["promote.skill-label-required"]
    assert row is not None


@pytest.mark.parametrize(
    "note",
    ["root AAAAAAAAAAAAAAAAAAAApw==", "size 3\nAAAAAAAAAAAAAAAAAAAApw=\nend",
     "checkpoint AAAAAAAAAAAAAAAAAAAApw= ok"],
)  # fmt: skip
def test_a_base64_token_inside_a_note_survives(note):
    from opentine._v3_guards import guarded_redaction

    assert guarded_redaction({"note": note}, where="test") == {"note": note}


def test_a_secret_after_a_base64_token_is_still_redacted():
    from opentine._v3_guards import guarded_redaction

    out = guarded_redaction({"n": "AAAAAAAAAAAAAAAAAAAApw=\npassword=hunter2"}, where="t")["n"]
    assert "hunter2" not in out and out.startswith("AAAAAAAAAAAAAAAAAAAApw=")
    for name in ("my_very_long_service_password", "MyVeryLongServicePassword"):
        out = guarded_redaction({"n": f"x\n{name}=\nhunter2"}, where="t")["n"]
        assert "hunter2" not in out, out
