"""0.51: the browser verifier reads bundles, and says which release it was built for.

The committed ``opentine/data/ui/tine-verifier.js`` (what ``tine ui`` serves)
is imported in Node and given every file of ``tests/_bundle_corpus.py``,
streamed from a ``Blob``: its verdict, reason, refs and digests must be
Python's. ts/browser-tests runs the same corpus, and the whole conformance
set, in real browsers.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from tests import _bundle_corpus

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "opentine" / "data" / "ui"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["version"]

CHECK = """
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { blobSource, verifyBundle, OPENTINE_VERSION } from "./tine-verifier.js";
const dir = process.argv[1];
const out = { version: OPENTINE_VERSION, reports: {} };
for (const name of readdirSync(dir).filter((n) => n.endsWith(".bundle")).sort()) {
  const blob = new Blob([readFileSync(join(dir, name))]);
  out.reports[name.slice(0, -7)] = await verifyBundle(blobSource(blob));
}
console.log(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def corpus(tmp_path_factory) -> tuple[Path, dict]:
    out = tmp_path_factory.mktemp("corpus")
    verdicts = _bundle_corpus.write(out / "files", out / "work")
    return out / "files", verdicts


def _node(script: str, *args: str) -> dict:
    done = subprocess.run([NODE, "--input-type=module", "-e", script, *args],
                          capture_output=True, text=True, timeout=300, cwd=UI)  # fmt: skip
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_the_corpus_reaches_every_refusal_and_every_bundle_shape(corpus):
    _files, verdicts = corpus
    assert sum(v["ok"] for v in verdicts.values()) >= 6
    reasons = {v["reason"].split(":")[0] for v in verdicts.values() if v["reason"]}
    for expected in ("bundle checksum mismatch (truncated or tampered)", "bundle pack is invalid",
                     "unsafe bundle ref", "invalid bundle signatures", "invalid bundle tombstones",
                     "bundle pack digest mismatch", "invalid bundle manifest shape"):  # fmt: skip
        assert expected in reasons


@needs_node
def test_the_shipped_browser_verifier_gives_pythons_bundle_verdicts(corpus):
    files, verdicts = corpus
    found = _node(CHECK, files.as_posix())
    assert found["version"] == VERSION
    for name, want in verdicts.items():
        got = found["reports"][name]
        assert got["ok"] == want["ok"], (name, want["reason"], got["reason"])
        assert got["opentine_version"] == VERSION
        if want["ok"]:
            assert got["refs"] == want["refs"], name
            assert (got["bundle"], got["pack"], got["objects"]) == (
                want["bundle"],
                want["pack"],
                want["objects"],
            ), name
            assert got["content_unavailable"] == want["content_unavailable"], name
            if want["redacted_public"]:
                assert got["redacted_public"]["state"] == want["redacted_public"]["state"], name
        elif want["reason"]:
            assert got["reason"].split(":")[0] == want["reason"].split(":")[0], name
            assert got["code"].startswith("bundle."), name
        # a check the reader did not run is never reported as passed
        assert all(row["state"] in ("pass", "fail", "unchecked") for row in got["checks"])
        if not got["ok"]:
            assert any(row["state"] == "fail" for row in got["checks"]) or got["redacted_public"]


@needs_node
def test_a_v3_bundle_is_streamed_one_object_at_a_time(corpus):
    files, _verdicts = corpus
    reports = _node(CHECK, files.as_posix())["reports"]
    assert reports["v3-two-refs"]["pack_reader"] == "streamed"
    assert reports["v5-two-refs"]["pack_reader"] == "in-memory"
    # A refusal inside the pack is re-derived by the exact reader, with its code.
    assert (
        reports["pack-trailing-bytes"]["code"] == "bundle.pack-invalid:pack.truncated-or-trailing"
    )


def test_the_client_version_manifest_matches_the_release():
    manifest = json.loads((ROOT / "docs" / "api" / "client-versions.json").read_text("utf-8"))
    assert manifest["manifest_version"] == 1
    assert manifest["current_release"] == VERSION
    browser = manifest["browser_verifier"]
    assert browser["built_for"] == VERSION

    def key(text: str) -> tuple[int, ...]:
        return tuple(int(part) for part in text.split("."))

    assert key(browser["minimum_supported"]) <= key(VERSION)
    source = (ROOT / "ts" / "verifier" / "src" / "version.ts").read_text("utf-8")
    assert re.search(r'OPENTINE_VERSION = "([^"]+)"', source).group(1) == VERSION
    assert f'"{VERSION}"' in (UI / "tine-verifier.js").read_text("utf-8")
