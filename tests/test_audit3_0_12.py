"""0.12 audit round 3: bisect score trust, .tineignore quoting, pack4 shallow typing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentine import _tineignore, cli
from opentine._git_link_runs import open_catalog
from opentine.graph import Run, StepKind
from opentine.kernel import KernelError
from opentine.repository import Repo, _pack4
from opentine.repository.pack import inspect_pack
from tests.test_pack4_0_12 import _parts, _rebuild
from tests.test_pack4_0_12 import _repo as _pack_repo


def _scored(tmp_path: Path):
    from opentine._cli_bisect import _scores

    store = Repo.init(tmp_path / "r")
    run = Run(id="scored1")
    run.add_step(StepKind.done, {"text": "x"})
    oid = store.put_run(run, ref="heads/main").run_id
    return store, oid, lambda **kw: _scores(open_catalog(str(store.path), tmp_path), oid, **kw)


def test_bisect_score_prefers_signed_and_bounds_unsigned(tmp_path):
    store, oid, scores = _scored(tmp_path)
    store.attest(oid, {"kind": "evaluation", "scores": {"q": 1e300}}, signer="mcp")
    assert scores() == {}
    store.attest(oid, {"kind": "evaluation", "scores": {"q": 0.9}}, signer="mcp")
    assert scores() == {"q": 0.9}
    assert scores(signed_only=True) == {}
    key = os.urandom(32)
    store.attest(oid, {"kind": "evaluation", "scores": {"q": 0.1}}, signer="ci", key=key)
    assert scores() == {"q": 0.1} and scores(signed_only=True) == {"q": 0.1}


def test_bisect_run_accepts_signed_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    parser = cli.build_parser() if hasattr(cli, "build_parser") else None
    if parser is not None:
        args = parser.parse_args(["bisect", "run", "--score", "q>=0.5", "--signed-only"])
        assert args.signed_only is True


@pytest.mark.parametrize(
    "header",
    [
        'diff --git "a/secrets/k\\303\\251.env" "b/secrets/k\\303\\251.env"',
        'diff --git "a/secrets/a\\"q.env" "b/secrets/a\\"q.env"',
        "diff --git a/secrets/plain.env b/secrets/plain.env",
    ],
)
def test_tineignore_matches_quoted_paths(header):
    patch = f"{header}\n--- x\n+++ y\n@@ -0,0 +1 @@\n+SECRET\n"
    assert "SECRET" not in _tineignore.filter_patch(patch, _tineignore.parse("secrets/\n"))
    redacted = _tineignore.filter_patch(patch, _tineignore.parse("redact:secrets/\n"))
    assert "SECRET" not in redacted and _tineignore.REDACTED in redacted


def test_tineignore_drops_unparseable_headers_and_rename_sources():
    rules = _tineignore.parse("secrets/\n")
    bad = 'diff --git "a/unterminated\n+SECRET\n'
    assert "SECRET" not in _tineignore.filter_patch(bad, rules)
    rename = "diff --git a/secrets/k b/public/k\n+SECRET\n"
    assert "SECRET" not in _tineignore.filter_patch(rename, rules)
    kept = "diff --git a/src/x.py b/src/x.py\n+fine\n"
    assert _tineignore.filter_patch(kept, rules) == kept


@pytest.mark.parametrize("shallow", ["abc", [1], {"a": 1}])
def test_pack4_malformed_shallow_is_a_kernel_error(tmp_path, shallow):
    repo, _ = _pack_repo(tmp_path)
    header, body = _parts(_pack4.from_v3(repo.pack(), "zlib"))
    header["shallow"] = shallow
    with pytest.raises(KernelError):
        inspect_pack(_rebuild(header, body))
