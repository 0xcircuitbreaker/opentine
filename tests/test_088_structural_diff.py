"""0.88: ``tine lineage diff``, the signed structural diff between two variants.

Each fixture plants one edit built to look like no change and asserts the diff
lists the file and names how it changed: a default argument, a zero-width
character in a string, a look-alike letter in a prompt, a Trojan-source bidi
control in a comment, a tool whose schema changed under its old name and
description, a config value that became another type, and duplicate keys.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine._sdiff import DiffRefused, check, compute, dumps, sign
from tests.promote_helpers import AT, PROMOTER, key, write_key

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

BASE = {
    "agent.py": 'def act(x, retries=3):\n    return "ok:" + x\n\n\nclass Tool:\n'
    "    def run(self):\n        return 1\n",
    "prompts/system.md": "# Role\nYou are careful.\n\n## Rules\nNever delete files.\n",
    "tools.json": json.dumps(
        {
            "tools": [
                {"name": "shell", "description": "Run a command", "inputSchema": {"type": "object"}}
            ]
        }
    ),  # fmt: skip
    "settings.json": json.dumps({"permissions": {"allow": ["read"]}, "max_turns": 5}),
    "config.toml": 'model = "m1"\n[limits]\ntokens = 100\n',
    "skills/search/SKILL.md": "# Search\nSearch the web.\n",
    "run.js": "function go(a) { return a + 1; }\n",
}


def tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return root


def pair(tmp_path: Path, **edits: str) -> tuple[Path, Path]:
    changed = {k.replace("__", "/").replace("_DOT_", "."): v for k, v in edits.items()}
    return tree(tmp_path / "old", BASE), tree(tmp_path / "new", {**BASE, **changed})


def files(claim: dict) -> dict[str, dict]:
    return {row["path"]: row for row in claim["files"]}


def _tine(capsys, *argv: str) -> tuple[int, dict | str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    if out.strip().startswith("{"):
        document = json.loads(out)
        assert _schemas.validate_output(document) == [], document
        return code, document
    return code, out


def test_identical_trees_have_no_changed_file(tmp_path):
    old, new = pair(tmp_path)
    claim = compute(old, new)
    assert claim["files"] == [] and claim["totals"]["files"] == len(BASE)
    assert claim["from"]["tree"] == claim["to"]["tree"]


def test_a_changed_default_argument_is_a_changed_symbol_not_a_new_line(tmp_path):
    text = BASE["agent.py"].replace("retries=3", "retries=0")
    old, new = pair(tmp_path, agent_DOT_py=text)
    row = files(compute(old, new))["agent.py"]
    assert row["kind"] == "python" and row["structural"]
    assert row["changes"] == [{"op": "changed", "item": "act"}]


def test_comments_and_formatting_are_listed_but_not_structural(tmp_path):
    text = "# reformatted\n" + BASE["agent.py"].replace("return 1", "return  1  # same")
    old, new = pair(tmp_path, agent_DOT_py=text.replace("\n", "\r\n"))
    row = files(compute(old, new))["agent.py"]
    assert row["structural"] is False and row["changes"] == []
    assert "line-endings" in row["flags"] and row["before"] != row["after"]


def test_a_zero_width_character_in_a_string_changes_the_symbol_and_is_flagged(tmp_path):
    text = BASE["agent.py"].replace('"ok:"', '"ok​:"')
    old, new = pair(tmp_path, agent_DOT_py=text)
    row = files(compute(old, new))["agent.py"]
    assert row["changes"] == [{"op": "changed", "item": "act"}]
    assert row["flags"] == ["invisible"]


def test_a_bidi_control_in_a_comment_is_flagged_even_without_a_structural_change(tmp_path):
    text = BASE["agent.py"].replace("class Tool:", "class Tool:  # ‮ignored‬")
    old, new = pair(tmp_path, agent_DOT_py=text)
    row = files(compute(old, new))["agent.py"]
    assert row["structural"] is False and "bidi" in row["flags"]


def test_an_nfkc_equal_identifier_is_flagged(tmp_path):
    text = BASE["agent.py"].replace("def act(x,", "def ａct(x,")  # fullwidth a
    old, new = pair(tmp_path, agent_DOT_py=text)
    row = files(compute(old, new))["agent.py"]
    assert row["structural"] is False  # Python reads the name as "act"
    assert {"nfkc", "non-ascii"} <= set(row["flags"])


def test_a_cyrillic_letter_in_a_prompt_section_is_a_changed_section(tmp_path):
    text = BASE["prompts/system.md"].replace("Never delete", "Nеver delete")
    old, new = pair(tmp_path, prompts__system_DOT_md=text)
    row = files(compute(old, new))["prompts/system.md"]
    assert row["kind"] == "prompt"
    assert row["changes"] == [{"op": "changed", "item": "Role / Rules", "flags": ["non-ascii"]}]


def test_an_added_prompt_section_and_reordering_are_reported(tmp_path):
    text = "## Rules\nNever delete files.\n# Role\nYou are careful.\n\n## Tools\nUse all.\n"
    old, new = pair(tmp_path, prompts__system_DOT_md=text)
    ops = {(c["op"], c["item"]) for c in files(compute(old, new))["prompts/system.md"]["changes"]}
    assert ("added", "Role / Tools") in ops and ("added", "Rules") in ops
    assert ("removed", "Role / Rules") in ops


def test_a_tool_that_keeps_its_name_and_description_but_changes_its_schema(tmp_path):
    schema = {"type": "object", "properties": {"cmd": {"type": "string"}}}
    text = json.dumps({"tools": [{"name": "shell", "description": "Run a command",
                                  "inputSchema": schema}]})  # fmt: skip
    old, new = pair(tmp_path, tools_DOT_json=text)
    row = files(compute(old, new))["tools.json"]
    assert row["kind"] == "tools"
    [change] = row["changes"]
    assert change["op"] == "changed" and change["item"] == "shell"
    assert change["before"] != change["after"] and change["after"].startswith("sha256:")


def test_a_tool_list_inside_a_settings_file_does_not_hide_the_other_keys(tmp_path):
    doc = {"tools": json.loads(BASE["tools.json"])["tools"], "allow": ["read"]}
    old = tree(tmp_path / "old", {"s.json": json.dumps(doc)})
    new = tree(tmp_path / "new", {"s.json": json.dumps({**doc, "allow": ["read", "write"]})})
    row = files(compute(old, new))["s.json"]
    assert row["kind"] == "config" and [c["item"] for c in row["changes"]] == ["allow[1]"]


def test_reordered_tools_and_keys_are_not_structural(tmp_path):
    settings = json.dumps({"max_turns": 5, "permissions": {"allow": ["read"]}}, indent=4)
    old, new = pair(tmp_path, settings_DOT_json=settings)
    row = files(compute(old, new))["settings.json"]
    assert row["kind"] == "config" and row["structural"] is False


def test_a_value_that_changes_type_is_a_config_change(tmp_path):
    old, new = pair(tmp_path, settings_DOT_json=BASE["settings.json"].replace("5", '"5"'),
                    config_DOT_toml=BASE["config.toml"].replace("100", "100.0"))  # fmt: skip
    rows = files(compute(old, new))
    assert [c["item"] for c in rows["settings.json"]["changes"]] == ["max_turns"]
    assert [c["item"] for c in rows["config.toml"]["changes"]] == ["limits.tokens"]


@pytest.mark.parametrize(("name", "text"), [
    ("settings.json", '{"permissions": {"allow": ["read"]}, "max_turns": 5, "max_turns": 50}'),
    ("config.toml", 'model = "m1"\nmodel = "m2"\n'),
])  # fmt: skip
def test_a_duplicate_key_refuses_the_diff(tmp_path, name, text):
    old, new = pair(tmp_path, **{name.replace(".", "_DOT_"): text})
    with pytest.raises(DiffRefused) as caught:
        compute(old, new)
    assert caught.value.code == "lineage-diff.duplicate-key"


def test_a_duplicate_yaml_key_refuses_the_diff(tmp_path):
    pytest.importorskip("yaml")
    old = tree(tmp_path / "old", {"c.yaml": "a: 1\nb: 2\n"})
    new = tree(tmp_path / "new", {"c.yaml": "a: 1\nb: 2\na: 3\n"})
    with pytest.raises(DiffRefused):
        compute(old, new)


def test_other_languages_get_a_token_diff(tmp_path):
    old, new = pair(tmp_path, run_DOT_js="function go(a) {\n  return a + 2;\n}\n")
    row = files(compute(old, new))["run.js"]
    assert row["kind"] == "text" and (row["inserted"], row["deleted"]) == (1, 1)


def test_added_and_removed_files_and_binaries(tmp_path):
    old, new = pair(tmp_path)
    (new / "skills" / "search" / "SKILL.md").unlink()
    (new / "hooks").mkdir()
    (new / "hooks" / "pre.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (new / "blob.bin").write_bytes(b"\xff\x00")
    rows = files(compute(old, new))
    assert rows["skills/search/SKILL.md"]["status"] == "removed"
    assert rows["hooks/pre.sh"]["status"] == "added"
    assert rows["blob.bin"]["kind"] == "binary"


def test_a_signed_diff_verifies_and_detects_a_later_edit(tmp_path):
    old, new = pair(tmp_path, agent_DOT_py=BASE["agent.py"].replace("3", "4"))
    path = tmp_path / "diff.json"
    path.write_bytes(dumps(sign(compute(old, new), key(PROMOTER), at=AT)))
    assert check(path, old, new)["ok"]
    (new / "agent.py").write_bytes(BASE["agent.py"].encode())
    assert [f["code"] for f in check(path, old, new)["findings"]] == ["lineage-diff.mismatch"]
    doc = json.loads(path.read_bytes())
    doc["claim"]["totals"]["changed"] = 0
    path.write_bytes(json.dumps(doc).encode())
    assert "lineage-diff.bad-signature" in {f["code"] for f in check(path)["findings"]}


def test_the_cli_signs_into_the_lineage_folder_and_binds_variants(tmp_path, capsys):
    from opentine._lineage import record

    old, new = pair(tmp_path, tools_DOT_json='{"tools": []}')
    lineage = tmp_path / "lineage"
    code, tree_row = _tine(capsys, "lineage", "diff", new.as_posix(), "--tree", "--json")
    assert code == 0
    digest = tree_row["trees"][0]["tree"]
    run = "run:sha256:" + "b" * 64
    variant = record(key(PROMOTER), run=run, artifacts={"skill": digest}, store=lineage,
                     at=AT)["variant"]  # fmt: skip
    keyfile = write_key(tmp_path / "k", PROMOTER)
    code, row = _tine(capsys, "lineage", "diff", old.as_posix(), new.as_posix(), "--to", variant,
                      "--key", keyfile.as_posix(), "--dir", lineage.as_posix(), "--at", AT,
                      "--json")  # fmt: skip
    assert code == 0 and row["claim"]["to"] == {"tree": digest, "variant": variant, "bound": True}
    assert Path(row["signed"]).parent == lineage / "diffs"
    code, checked = _tine(capsys, "lineage", "diff", "--check", row["signed"], old.as_posix(),
                          new.as_posix(), "--dir", lineage.as_posix(), "--json")  # fmt: skip
    assert code == 0 and checked["ok"] and checked["target"] == variant
    code, _ = _tine(capsys, "lineage", "diff", old.as_posix(), new.as_posix(), "--to",
                    "sha256:" + "0" * 64, "--dir", lineage.as_posix())  # fmt: skip
    assert code != 0
    code, text = _tine(capsys, "lineage", "diff", old.as_posix(), new.as_posix())
    assert code == 0 and "changed tools tools.json" in text


def test_check_without_trees_reports_bound_unverified_and_rsi_refuses(tmp_path, capsys):
    from tests.promote_helpers import policy

    old, new = pair(tmp_path, agent_DOT_py=BASE["agent.py"].replace("3", "4"))
    path = tmp_path / "diff.json"
    path.write_bytes(dumps(sign(compute(old, new), key(PROMOTER), at=AT)))
    alone = check(path)
    assert alone["ok"] and alone["bound"] == "unverified"
    assert check(path, old, new)["bound"] == "recomputed"
    assert [f["code"] for f in check(path, rsi=True)["findings"]] == ["lineage-diff.mismatch"]
    assert check(path, old, new, rsi=True)["ok"]
    rsi = policy(tmp_path, require_holdout=False, profile="rsi")
    code, row = _tine(capsys, "lineage", "diff", "--check", path.as_posix(), "--policy",
                      rsi.as_posix(), "--json")  # fmt: skip
    assert code == 1 and row["bound"] == "unverified" and not row["ok"]
    code, row = _tine(capsys, "lineage", "diff", "--check", path.as_posix(), "--json")
    assert code == 0 and row["bound"] == "unverified"
