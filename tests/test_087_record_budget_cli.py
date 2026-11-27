"""0.87: ``tine record --budget`` and ``tine budget sign-policy`` model-path flags, end to end."""

from __future__ import annotations

import json
import sys
import threading

import pytest

from opentine import _budget_ledger, _budget_policy, cli
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.record_budget_helpers import SEEDS, fpr, key
from tests.test_087_record_budget import SUBJECT, T0, Upstream

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CHILD = """
import json, os, urllib.request, urllib.error
base = os.environ["OPENAI_BASE_URL"]
for model in ("gpt-4o-mini", "gpt-4o"):
    req = urllib.request.Request(base + "/chat/completions", method="POST",
        data=json.dumps({"model": model, "max_tokens": 5}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        print(model, urllib.request.urlopen(req, timeout=30).status)
    except urllib.error.HTTPError as exc:
        print(model, exc.code)
"""


def _main(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    return 0


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [fpr("runner")], "policy": [fpr("policy")]}
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    for name in SEEDS:
        (tmp_path / f"{name}.key").write_bytes(bytes([SEEDS[name]]).hex().encode() * 32)
    up = Upstream()
    threading.Thread(target=up.serve_forever, daemon=True).start()
    yield tmp_path, repo, up
    up.shutdown()
    up.server_close()


def test_sign_policy_writes_a_model_path_section(setup, capsys):
    tmp, repo, _ = setup
    out = tmp / "p.json"
    assert _main("budget", "sign-policy", SUBJECT, "--serial", "1", "--tokens", "100000",
                 "--allow-model", "OpenAI/GPT-4o-Mini", "--model-alias", "fast=gpt-4o-mini",
                 "--judge-tokens", "50", "--key", str(tmp / "policy.key"), "--out",
                 str(out), "--json") == 0  # fmt: skip
    doc = json.loads(out.read_bytes())
    assert doc["model_path"]["allow"] == ["gpt-4o-mini"]
    assert doc["model_path"]["aliases"] == {"fast": "gpt-4o-mini"}
    assert _budget_policy.signer(doc) == fpr("policy")
    capsys.readouterr()


def test_record_with_a_budget_refuses_a_model_outside_the_allowlist(setup, capfd):
    tmp, repo, up = setup
    doc = _budget_policy.sign(_budget_policy.build(
        SUBJECT, {"tokens": 100000}, serial=1, on_limit="deny", issued_at="2027-01-15T08:00:00Z",
        model_path={"allow": ["gpt-4o-mini"]}), key("policy"))  # fmt: skip
    _budget_ledger.append(repo, SUBJECT, "policy", {"policy": doc}, key("runner"), at_ms=T0)
    code = _main("record", "--budget", SUBJECT, "--budget-key", str(tmp / "runner.key"),
                 "--repo", str(repo.path), "--upstream",
                 f"openai=http://127.0.0.1:{up.server_address[1]}", "--save",
                 str(tmp / "run.tine"), "--", sys.executable, "-c", CHILD)  # fmt: skip
    out = capfd.readouterr().out
    assert code == 0
    assert "gpt-4o-mini 200" in out and "gpt-4o 403" in out
    assert len(up.seen) == 1
    entries = _budget_ledger.entries(repo, SUBJECT)
    assert [r["value"]["entry"] for r in entries].count("deny") == 1
    from opentine.core import Run

    run = Run.load(tmp / "run.tine")
    assert run.metadata["record"]["budget"]["subject"] == SUBJECT
    assert len(run.steps) == 2


def test_record_budget_needs_a_key(setup, capsys):
    tmp, repo, _ = setup
    assert _main("record", "--budget", SUBJECT, "--repo", str(repo.path), "--",
                 sys.executable, "-c", "pass") == 2  # fmt: skip
    capsys.readouterr()


def test_the_ledger_lock_file_does_not_upset_fsck(setup, capsys):
    tmp, repo, _ = setup
    _budget_ledger.append(repo, SUBJECT, "flag", {"code": "x", "detail": "y", "about": None},
                          key("runner"), at_ms=T0)  # fmt: skip
    assert (repo.path / "budget-ledger.lock").exists()
    assert _main("fsck", "--repo", str(repo.path)) == 0
    capsys.readouterr()
