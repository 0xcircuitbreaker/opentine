"""0.48: the IDE extensions read exactly what ``tine blame --lines --json`` and ``tine why`` print.

The VS Code extension (``ide/vscode``) and the JetBrains plugin
(``ide/jetbrains``) are thin clients of the CLI. Their shared fixture must be a
valid ``tine-blame/1`` per-line record, and the real commands, run on a
repository with an attributed agent commit, must carry every key the
extensions read. The packaging rules are pinned too: exact dev-dependency
versions, a lockfile, a CI step, and ``ide/`` kept out of the sdist.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from opentine import _schemas
from tests.test_045_blame_attach import _json, repo  # noqa: F401 - the attributed repository

ROOT = Path(__file__).resolve().parents[1]
IDE = ROOT / "ide"
FIXTURE = IDE / "vscode" / "test" / "fixtures" / "blame-lines.json"
LINE_KEYS = {"line", "commit", "author", "summary", "ai"}
AI_KEYS = {"run", "seq", "model"}
WHY_KEYS = {"path", "line", "commit", "run", "attribution", "slice"}


def test_the_shared_fixture_is_a_valid_per_line_blame_record():
    record = json.loads(FIXTURE.read_text("utf-8"))
    assert _schemas.validate_output(record) == []
    assert _schemas.detect(record) == "tine-blame-1"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_the_real_commands_carry_every_key_the_extensions_read(repo, capsys):  # noqa: F811
    assert _json(capsys, "attach", "runattr45", "HEAD")[0] == 0
    code, record = _json(capsys, "blame", "a.py", "--lines")
    assert code == 0 and record["schema"] == "tine-blame/1"
    assert {"path", "total_lines", "ai_lines", "lines"} <= set(record)
    for row in record["lines"]:
        assert LINE_KEYS <= set(row) and isinstance(row["line"], int) and row["line"] >= 1
        assert row["ai"] is None or AI_KEYS <= set(row["ai"])
    assert sum(1 for row in record["lines"] if row["ai"]) == record["ai_lines"] == 2
    code, why = _json(capsys, "why", "a.py:1")
    assert code == 0 and WHY_KEYS <= set(why) and why["run"] == "runattr45"
    assert isinstance(why["slice"], list) and why["slice"]


def test_the_vscode_extension_pins_its_tooling_and_runs_in_ci():
    package = json.loads((IDE / "vscode" / "package.json").read_text("utf-8"))
    assert "dependencies" not in package  # nothing ships at run time but our own code
    for name, version in package["devDependencies"].items():
        assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), (name, version)
    lock = json.loads((IDE / "vscode" / "package-lock.json").read_text("utf-8"))
    assert lock["lockfileVersion"] == 3
    commands = {c["command"] for c in package["contributes"]["commands"]}
    assert commands == {"opentine.toggleBlame", "opentine.verifyLine"}
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    step = ci[ci.index("working-directory: ide/vscode") :]
    assert "npm test" in step[:400] and "npm audit --audit-level=low" in step[:400]


def test_the_jetbrains_skeleton_names_its_actions_and_pins_its_build():
    plugin = (IDE / "jetbrains" / "src/main/resources/META-INF/plugin.xml").read_text("utf-8")
    for action in ("dev.opentine.ide.ToggleAiBlameAction", "dev.opentine.ide.VerifyLineAction"):
        assert f'class="{action}"' in plugin
        assert f"class {action.rsplit('.', 1)[1]}" in (
            IDE / "jetbrains/src/main/kotlin/dev/opentine/ide/Actions.kt"
        ).read_text("utf-8")
    build = (IDE / "jetbrains" / "build.gradle.kts").read_text("utf-8")
    for pinned in re.findall(r'version "([^"]+)"', build) + re.findall(r':([0-9][^"]*)"\)', build):
        assert re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", pinned), pinned
    assert "Not built in CI" in (IDE / "README.md").read_text("utf-8")
