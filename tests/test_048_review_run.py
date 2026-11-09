"""0.48: ``tine review run`` (reviewer fleets, signed findings) and ``tine graph``.

A fake reviewer harness (a Python script a trusted ``fleet.toml`` runs) reads the
change it is handed and writes findings; every well-formed one becomes a signed
``opentine.review-finding`` and the Review's next version lists it, so a
critical finding blocks the gate. ``tine graph`` maps a small mixed-language
tree with tree-sitter (when the ``graph`` extra is installed) and with the
regex fallback, and the MCP ``code_graph`` tool returns the same document.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _code_graph, _code_graph_ts, _review_finding, _review_run, _schemas, cli
from opentine._signed_record import RecordError
from opentine.repository import Repo

SEED, STRANGER = "ab" * 32, "cd" * 32
HARNESS = """\
import json, os, sys
context = open(os.environ["OPENTINE_REVIEW_CONTEXT"], encoding="utf-8").read()
rows = []
if "password" in context:
    rows.append({"severity": "critical", "message": "a password is hard-coded",
                 "path": "app.py", "line": 2})
rows.append({"severity": "low", "message": "reviewed " + os.environ["OPENTINE_REVIEW_ID"]})
with open(os.environ["OPENTINE_REVIEW_FINDINGS"], "w", encoding="utf-8") as out:
    for row in rows:
        out.write(json.dumps(row) + "\\n")
    out.write("not json\\n")
    out.write(json.dumps({"severity": "bogus", "message": "x"}) + "\\n")
"""


def _hex(seed: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    return key.public_key().public_bytes_raw().hex()


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out = capsys.readouterr().out
    document = json.loads(out) if out.strip().startswith("{") else {}
    if code == 0 and document:
        assert _schemas.validate_output(document) == [], document
    return code, document


def _git(root: Path, *argv: str) -> None:
    subprocess.run(["git", "-C", root.as_posix(), *argv], check=True, capture_output=True)


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    for name, value in (("GIT_AUTHOR_NAME", "T"), ("GIT_AUTHOR_EMAIL", "t@example.invalid"),
                        ("GIT_COMMITTER_NAME", "T"),
                        ("GIT_COMMITTER_EMAIL", "t@example.invalid")):  # fmt: skip
        monkeypatch.setenv(name, value)
    root = tmp_path / "w"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "-q", "-m", "init")
    (root / "app.py").write_text("def main():\n    password = 'hunter2'\n", encoding="utf-8")
    Repo.init(root)
    (tmp_path / "alice.key").write_text(SEED, encoding="utf-8")
    (tmp_path / "bob.key").write_text(STRANGER, encoding="utf-8")
    reviewers = tmp_path / "reviewers"
    reviewers.mkdir()
    (reviewers / "harness.py").write_text(HARNESS, encoding="utf-8")
    argv = json.dumps([sys.executable, (reviewers / "harness.py").as_posix()])
    (reviewers / "fleet.toml").write_text(
        f'[fleet]\nname = "reviewers"\n\n[[agents]]\nname = "fake"\nargv = {argv}\ncount = 2\n',
        encoding="utf-8",
    )
    return tmp_path


def _review(capsys, work: Path, *argv: str, key: str = "alice") -> tuple[int, dict]:
    return _tine(capsys, "review", *argv, "--ed25519-key-file", (work / f"{key}.key").as_posix(),
                 "--repo", (work / "w").as_posix(), "--json")  # fmt: skip


def test_review_run_signs_every_finding_and_blocks_the_gate(work, capsys):
    code, _ = _review(capsys, work, "create", "auth", "--title", "Auth", "--gate", "ship")
    assert code == 0
    fleet = (work / "reviewers" / "fleet.toml").as_posix()
    code, out = _review(capsys, work, "run", "auth", "--fleet", fleet)
    assert code == 1 and "not trusted" in out["error"]["message"]  # it runs nothing
    code, out = _review(capsys, work, "run", "auth", "--fleet", fleet, "--trust")
    assert code == 0, out
    assert out["exit_code"] == 0 and len(out["members"]) == 2
    assert out["skipped"] == 4  # two malformed lines per member, never guessed at
    found = out["findings"]
    assert len(found) == 4 and {row["state"] for row in found} == {"verified"}
    assert {(r["severity"], r["path"], r["line"]) for r in found} == {
        ("critical", "app.py", 2), ("low", None, None)}  # fmt: skip
    stored = _review_run.load(Repo.open(work / "w"), "auth")
    assert len(stored) == 4
    for record in stored:
        assert _schemas.validate(record) == ("opentine-review-finding-1", [])
        assert _review_finding.check(record, reviewers=[_hex(SEED)])["state"] == "verified"
        assert "hunter2" not in json.dumps(record)
    with pytest.raises(RecordError) as caught:
        _review_finding.check(stored[0], reviewers=[_hex(STRANGER)])
    assert caught.value.code == "review-finding.untrusted-signer"
    code, out = _tine(capsys, "review", "findings", "auth", "--repo", (work / "w").as_posix(),
                      "--json")  # fmt: skip
    assert code == 0 and len(out["findings"]) == 4
    code, out = _tine(capsys, "review", "show", "auth", "--repo", (work / "w").as_posix(),
                      "--json")  # fmt: skip
    head = out["version"]
    assert head["seq"] == 1 and {f["id"] for f in head["findings"]} == {
        r["finding_id"] for r in stored
    }
    code, out = _review(capsys, work, "gate", "auth", "ship", "--approve")
    assert code == 4 and "critical finding" in out["error"]["message"], out


def test_review_run_refuses_a_key_that_is_not_a_reviewer(work, capsys):
    assert _review(capsys, work, "create", "auth", "--title", "Auth")[0] == 0
    fleet = (work / "reviewers" / "fleet.toml").as_posix()
    code, _ = _review(capsys, work, "run", "auth", "--fleet", fleet, "--trust", key="bob")
    assert code != 0
    assert _review_run.load(Repo.open(work / "w"), "auth") == []


def test_a_tampered_finding_fails_and_a_bad_path_is_malformed():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
    record = _review_finding.sign(_review_finding.build("auth", "rf-1", "high", "m",
                                                        reviewer="fake-0", path="a/b.py",
                                                        line=3), key)  # fmt: skip
    assert _review_finding.check(record)["state"] == "verified-tofu"
    with pytest.raises(RecordError, match="does not hold"):
        _review_finding.check({**record, "line": 4})
    for path in ("/etc/passwd", "a/../b", "a//b", "C:\\x"):
        assert not _review_finding.path_ok(path)
    with pytest.raises(RecordError) as caught:
        _review_finding.build("auth", "rf-1", "high", "m", reviewer="x", line=3)
    assert caught.value.code == "review-finding.malformed"


# --- tine graph ---------------------------------------------------------------- #


def _tree(root: Path) -> None:
    files = {
        "pkg/__init__.py": "",
        "pkg/core.py": "import os\nfrom pkg import util\n\nclass Store:\n    def get(self):\n"
        "        return 1\n\nasync def load():\n    pass\n",
        "pkg/util.py": "def helper():\n    return 'class Fake:'\n",
        "web/main.ts": "import { x } from './lib';\nexport class App {}\n"
        "export interface Props {}\nexport function run() {}\n",
        "web/lib.ts": "export const x = (a: number) => a;\n",
        "cmd/main.go": 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println() }\n',
        "src/lib.rs": "pub struct Point;\npub(crate) fn area() {}\n",
        "ide/Plugin.kt": "class Gutter : Base {\n    override fun paint() {}\n}\n",
        "README.md": "# not code\n",
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _by_path(found: dict) -> dict:
    return {f["path"]: f for f in found["files"]}


@pytest.mark.parametrize("backend", ["regex", "tree-sitter"])
def test_graph_maps_symbols_imports_and_edges(tmp_path, capsys, monkeypatch, backend):
    if backend == "regex":
        monkeypatch.setattr(_code_graph_ts, "_parser", lambda: None)
    elif not _code_graph_ts.available():
        pytest.skip("the graph extra (tree-sitter) is not installed")
    _tree(tmp_path)  # no git work tree: a directory walk
    code, out = _tine(capsys, "graph", "--repo", tmp_path.as_posix(), "--json")
    assert code == 0 and out["schema"] == "tine-graph/1"
    files = _by_path(out)
    assert "README.md" not in files and out["tree_sitter"] is (backend == "tree-sitter")
    core = files["pkg/core.py"]
    assert core["backend"] == backend
    assert [(s["name"], s["kind"], s["line"], s["parent"]) for s in core["symbols"]] == [
        ("Store", "class", 4, None),
        ("get", "method", 5, "Store"),
        ("load", "function", 8, None),
    ]
    assert core["imports"] == ["os", "pkg"] or core["imports"] == ["os", "pkg.util", "pkg"]
    edges = {(e["from"], e["to"]) for e in out["edges"]}
    assert ("pkg/core.py", "pkg/__init__.py") in edges and ("web/main.ts", "web/lib.ts") in edges
    kinds = {(p, s["name"], s["kind"]) for p, f in files.items() for s in f["symbols"]}
    assert {("web/main.ts", "App", "class"), ("web/main.ts", "Props", "type"),
            ("web/lib.ts", "x", "function"), ("cmd/main.go", "main", "function"),
            ("src/lib.rs", "Point", "type"), ("src/lib.rs", "area", "function"),
            ("ide/Plugin.kt", "paint", "method")} <= kinds  # fmt: skip
    code, out = _tine(capsys, "graph", "--repo", tmp_path.as_posix(), "--symbol", "helper",
                      "--json")  # fmt: skip
    assert [f["path"] for f in out["files"]] == ["pkg/util.py"]


def test_graph_lists_tracked_files_only_in_a_git_work_tree(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_COMMITTER_NAME", "T")
    _tree(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "pkg")
    found = _code_graph.build(tmp_path)
    assert {f["path"] for f in found["files"]} == {"pkg/__init__.py", "pkg/core.py",
                                                   "pkg/util.py"}  # fmt: skip
    assert _code_graph.build(tmp_path, ["pkg/util.py"])["counts"]["files"] == 1


def test_a_finding_message_is_redacted_but_digests_and_oids_survive():
    oid = "run:sha256:" + "be" * 32
    line = json.dumps({"severity": "high", "message": f"{oid} at {'3b' * 20} leaks ghp_{'a' * 36}"})
    rows, skipped = _review_run.parse(line)
    assert skipped == 0 and oid in rows[0]["message"] and "3b" * 20 in rows[0]["message"]
    assert "ghp_" not in rows[0]["message"] and "[REDACTED]" in rows[0]["message"]
