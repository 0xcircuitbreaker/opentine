"""0.85 acceptance: scorer isolation and oversight protection, end to end."""

from __future__ import annotations

import hashlib
import json
import warnings

import pytest

from opentine import _scorer_closure as closure
from opentine._containment_detect import PATTERNS
from opentine._eval_run import verify_eval
from opentine._integrity_defaults import env_touches
from opentine._scorer_rescore import verify_report
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.scorer_isolation_helpers import HELPER, isolated_eval, room, run_json, scorer
from tests.test_064_oversight_floor import _pin
from tests.test_064_oversight_gate import _codes
from tests.test_064_oversight_gate import repo as repo  # noqa: F401 - the pinned fixture
from tests.test_085_oversight_pin import _restore_without_promotion_route

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
__all__ = ["room"]


def test_isolated_eval_pins_its_closure_and_a_trusted_rescore_agrees_then_catches_edits(
    capsys, room
):
    status, out = isolated_eval(capsys, room)
    assert status == 0 and out["advisories"] == []
    doc = json.loads((room / "ev" / "scorer.json").read_bytes())
    assert closure.pin(doc) == out["scorer_version"] and verify_eval(room / "ev")["ok"]
    argv = ("eval", "rescore", "ev", "--dataset", "d.jsonl", "--key", "k.key")
    status, re = run_json(capsys, *argv, "--out", "r.json")
    assert status == 0 and re["report"]["verdict"] == "agree"
    assert verify_report(json.loads((room / "r.json").read_bytes())) is None
    # A hostile scorer is refused and nothing is signed.
    spec = scorer(room, "bad", "import os\n\ndef score(output, item):\n    os.listdir('/')\n"
                  "    return 1\n")  # fmt: skip
    status, bad = run_json(capsys, "eval", "run", "d.jsonl", "--scorer", spec, "--isolate",
                           "--key", "k.key", "--out", "bad")  # fmt: skip
    assert status == 1 and bad["refusals"][0]["code"] == "scorer.isolation-breach"
    assert not (room / "bad").exists()
    # Editing a helper after the eval breaks the pin and the trusted rescore.
    (room / "sc" / "helper.py").write_bytes(HELPER + b"# edited\n")
    status, again = isolated_eval(capsys, room, "ev2", "--expect-closure", out["closure"])
    assert status == 1 and again["refusals"][0]["code"] == "scorer.closure-mismatch"
    status, re = run_json(capsys, *argv)
    assert status != 0 and not re["report"]["closure_agree"]
    # An in-process run is advisory by default (D12), never a refusal.
    status, plain = run_json(capsys, "eval", "run", "d.jsonl", "--scorer", "exact",
                             "--key", "k.key", "--out", "ep")  # fmt: skip
    assert status == 0
    assert [a["code"] for a in plain["advisories"]] in ([], ["advisory:scorer.in-process"])


def test_a_digest_pinned_trust_bundle_refuses_promotion_after_a_policy_rollback(repo):  # noqa: F811
    digest = hashlib.sha256((repo.path / "oversight.toml").read_bytes()).hexdigest()
    _pin(repo.path, {"version": 1, "policy_sha256": digest})
    _restore_without_promotion_route(repo)
    assert _codes(repo) == ["promote.oversight-insufficient"]


@pytest.mark.parametrize("command", ["export OPENTINE_HOOK=0", "env -i python loop.py"])
def test_switching_monitoring_off_is_a_limit_edit(command):
    assert env_touches(command) and PATTERNS["limit-edit"].search(command)


def test_deprecated_names_warn_and_keep_working():
    from opentine import policies

    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        assert policies.dev_profile(".") is not None
    assert any(issubclass(w.category, DeprecationWarning) for w in seen)
