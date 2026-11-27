"""0.87 acceptance, end to end through the CLI.

1. ``tine record --budget`` lets an allowlisted model through, refuses a model
   outside the allowlist, a judge call over the judge cap and a call over the
   token cap before any of them reaches the provider, and files one signed,
   held deny entry for each.
2. ``tine integrity region-pin`` signs the locked code of an EVOLVE-BLOCK file;
   ``tine integrity region-check`` passes an edit inside the region and reports
   one outside it.
"""

from __future__ import annotations

import json
import sys

import pytest

from opentine import _budget_ledger, _budget_policy
from opentine.repository._holds import BUDGET_LEDGER
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.record_budget_helpers import fpr, key
from tests.test_087_record_budget import SUBJECT, T0
from tests.test_087_record_budget_cli import _main, setup  # noqa: F401
from tests.test_087_regions import BASE

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CHILD = """
import json, os, urllib.request, urllib.error
base = os.environ["OPENAI_BASE_URL"]
calls = [("allowed", "gpt-4o-mini", 5, None), ("outside", "gpt-4o", 5, None),
         ("judge", "gpt-4o-mini", 500, "judge"), ("cap", "gpt-4o-mini", 5000, None)]
for name, model, limit, role in calls:
    headers = {"Content-Type": "application/json"}
    if role:
        headers["X-Opentine-Call-Role"] = role
    req = urllib.request.Request(base + "/chat/completions", method="POST",
        data=json.dumps({"model": model, "max_tokens": limit}).encode(), headers=headers)
    try:
        print(name, urllib.request.urlopen(req, timeout=30).status)
    except urllib.error.HTTPError as exc:
        print(name, exc.code, json.loads(exc.read())["error"]["code"])
"""


def test_record_budget_enforces_allowlist_judge_cap_and_budget(setup, capfd):  # noqa: F811
    tmp, repo, up = setup
    path = {"allow": ["gpt-4o-mini"], "judge": {"tokens": 100}}
    doc = _budget_policy.sign(_budget_policy.build(
        SUBJECT, {"tokens": 1000}, serial=1, on_limit="deny", issued_at="2027-01-15T08:00:00Z",
        model_path=path), key("policy"))  # fmt: skip
    _budget_ledger.append(repo, SUBJECT, "policy", {"policy": doc}, key("runner"), at_ms=T0)
    code = _main("record", "--budget", SUBJECT, "--budget-key", str(tmp / "runner.key"),
                 "--repo", str(repo.path), "--upstream",
                 f"openai=http://127.0.0.1:{up.server_address[1]}", "--save",
                 str(tmp / "run.tine"), "--", sys.executable, "-c", CHILD)  # fmt: skip
    lines = capfd.readouterr().out.splitlines()
    assert code == 0
    assert "allowed 200" in lines
    assert "outside 403 budget.model-not-allowed" in lines
    assert "judge 403 budget.judge-would-exceed" in lines
    assert any(line.startswith("cap 403 budget.") for line in lines)
    assert len(up.seen) == 1
    denies = [r for r in _budget_ledger.entries(repo, SUBJECT) if r["value"]["entry"] == "deny"]
    assert len(denies) == 3
    assert all(d["signed"] and d["signer"] == fpr("runner") for d in denies)
    held = _budget_ledger.held_ids(repo, BUDGET_LEDGER, SUBJECT)
    assert all(d["id"] in held for d in denies)


def test_region_pin_and_check_through_the_cli(setup, capsys):  # noqa: F811
    tmp, repo, _ = setup
    algo = repo.path.parent / "evolve" / "algo.py"
    algo.parent.mkdir()
    algo.write_bytes(BASE.encode("utf-8"))
    root = str(repo.path.parent)
    assert _main("integrity", "region-pin", "--repo", root, "--glob", "evolve/**",
                 "--key", str(tmp / "policy.key"), "--json") == 0  # fmt: skip
    capsys.readouterr()
    algo.write_bytes(BASE.replace("x * 2", "x * 3").encode("utf-8"))
    assert _main("integrity", "region-check", "--repo", root, "--json") == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    algo.write_bytes(BASE.replace("xs[-3:]", "xs").encode("utf-8"))
    assert _main("integrity", "region-check", "--repo", root, "--json") != 0
    row = json.loads(capsys.readouterr().out)
    assert row["ok"] is False and row["findings"]
