"""0.87: the signed region pin, its fail-closed load, promote and the CLI."""

from __future__ import annotations

import os
import sys

import pytest

from opentine._regions import ADDED, OUTSIDE, REMOVED
from tests.test_087_regions import BASE


@pytest.fixture
def tree(tmp_path, monkeypatch):
    from tests.key_roles_helpers import pin_roles
    from tests.promote_helpers import fingerprint
    from tests.regions_helpers import policy_role

    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    monkeypatch.delenv("OPENTINE_TRUST_OWNER", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_BUNDLE", raising=False)
    root = tmp_path / "repo"
    (root / ".tine").mkdir(parents=True)
    (root / "evolve").mkdir()
    (root / "evolve" / "algo.py").write_bytes(BASE.encode())
    (root / "evolve" / "notes.md").write_bytes(b"locked notes\n")
    (root / "other.py").write_bytes(b"outside the globs\n")
    roles = f'version = 1\n[roles]\n{policy_role()}optimizer = ["{fingerprint("9e" * 32)}"]\n'
    (root / ".tine" / "key-roles.toml").write_bytes(roles.encode())
    pin_roles(root / ".tine")
    return root


def _write(path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def test_pin_then_check_reports_each_hostile_edit(tree):
    from opentine._regions_pin import check
    from tests.regions_helpers import pin_regions

    row = pin_regions(tree)
    assert row["files"] == 2 and row["regions"] == 1
    assert check(tree)["ok"]
    _write(tree / "other.py", "free to change\n")
    _write(tree / "evolve" / "algo.py", BASE.replace("x * 2", "x * 3"))
    assert check(tree)["ok"]
    _write(tree / "evolve" / "algo.py", BASE.replace("xs[-3:]", "xs"))
    _write(tree / "evolve" / "new.py", "planted = True\n")
    (tree / "evolve" / "notes.md").unlink()
    found = check(tree)
    pairs = {(f["code"], f["path"]) for f in found["findings"]}
    assert not found["ok"] and pairs == {(OUTSIDE, "evolve/algo.py"), (ADDED, "evolve/new.py"),
                                         (REMOVED, "evolve/notes.md")}  # fmt: skip


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_symlink_is_pinned_as_its_target_never_followed(tree):
    from opentine._regions_pin import check
    from tests.regions_helpers import pin_regions

    os.symlink("algo.py", tree / "evolve" / "link.py")
    pin_regions(tree)
    _write(tree / "evolve" / "algo.py", BASE.replace("x * 2", "x * 5"))
    assert check(tree)["ok"]
    (tree / "evolve" / "link.py").unlink()
    os.symlink("../other.py", tree / "evolve" / "link.py")
    assert [f["code"] for f in check(tree)["findings"]] == [OUTSIDE]


def test_the_pin_fails_closed(tree):
    import json

    from opentine._regions_pin import MISSING, PIN, UNSIGNED, check, pin
    from tests.promote_helpers import key
    from tests.regions_helpers import AT, pin_regions

    assert [f["code"] for f in check(tree)["findings"]] == [MISSING]
    with pytest.raises(ValueError, match="policy-role"):
        pin(tree, ["evolve/**"], key("9e" * 32), AT)  # an optimizer key never pins
    pin_regions(tree)
    doc = json.loads((tree / PIN).read_bytes())
    doc["claim"]["files"].pop("evolve/notes.md")  # the loop drops a file from the pin
    (tree / PIN).write_bytes(json.dumps(doc).encode())
    assert [f["code"] for f in check(tree)["findings"]] == [UNSIGNED]
    (tree / PIN).write_bytes(b"[" * 100_000)
    assert [f["code"] for f in check(tree)["findings"]] == [UNSIGNED]


def test_a_baseline_with_bad_markers_is_never_pinned(tree):
    from tests.regions_helpers import pin_regions

    _write(tree / "evolve" / "algo.py", BASE.replace("# EVOLVE-BLOCK-END\n", ""))
    with pytest.raises(ValueError, match="never closed"):
        pin_regions(tree)


def test_promote_advises_by_default_and_refuses_when_required(tree):
    from opentine._regions_pin import check_policy, promote_findings
    from tests.regions_helpers import pin_regions

    default, required, rsi = {}, {"regions": "required"}, {"profile": "rsi"}
    for policy in (default, required, rsi):
        check_policy(policy)
    assert rsi["regions"] == "required"
    with pytest.raises(ValueError, match="rsi profile"):
        check_policy({"profile": "rsi", "regions": "advisory"})
    with pytest.raises(ValueError, match="regions is one of"):
        check_policy({"regions": "off"})
    assert promote_findings(default, tree) == ([], [])  # D12: nothing configured
    assert [r["code"] for r in promote_findings(required, tree)[0]] == ["promote.regions-unpinned"]
    assert [r["code"] for r in promote_findings(rsi, None)[0]] == ["promote.regions-unpinned"]
    pin_regions(tree)
    assert promote_findings(required, tree) == ([], [])
    _write(tree / "evolve" / "algo.py", BASE.replace("xs[-3:]", "xs"))
    refused, advised = promote_findings(default, tree)
    assert refused == [] and [a["code"] for a in advised] == ["advisory:regions.outside-modified"]
    assert [r["code"] for r in promote_findings(rsi, tree)[0]] == ["promote.region-modified"]


def test_the_cli_pins_and_checks_with_a_schema(tree, capsys):
    import json

    from opentine import _schemas, cli
    from tests.promote_helpers import write_key
    from tests.regions_helpers import POLICY

    keyfile = write_key(tree.parent / "policy.key", POLICY)
    repo = ["--repo", tree.as_posix(), "--json"]

    def tine(*argv: str) -> tuple[int, dict]:
        try:
            cli.main(list(argv))
            code = 0
        except SystemExit as exc:
            code = int(exc.code or 0)
        row = json.loads(capsys.readouterr().out)
        assert _schemas.validate_output(row) == [], row
        return code, row

    code, row = tine("integrity", "region-pin", "--glob", "evolve/**", "--key",
                     keyfile.as_posix(), "--at", "2026-11-27T00:00:00Z", *repo)  # fmt: skip
    assert code == 0 and row["files"] == 2
    assert tine("integrity", "region-check", *repo)[0] == 0
    _write(tree / "evolve" / "algo.py", BASE.replace("import math", "import os"))
    code, row = tine("integrity", "region-check", *repo)
    assert code == 1 and [f["code"] for f in row["findings"]] == [OUTSIDE]
    code, row = tine("integrity", "check", "run:sha256:" + "b" * 64, *repo)
    assert code == 1 and OUTSIDE in {f["code"] for f in row["findings"]}
