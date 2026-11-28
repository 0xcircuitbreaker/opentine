"""0.88: the ``skill`` lineage slot and skill labels in ``tine promote``.

A candidate whose signed lineage record names another skill tree than the
holder's is a skill change: shown as ``skills`` in the result and the signed
decision, advisory under a non-skill label by default (D12), refused under
``skill_labels = "required"``; a ``skill.*`` label moves and reverts normally.
"""

from __future__ import annotations

import json

import pytest

from opentine._lineage import record
from opentine._promote_skill import check_policy, findings
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import AT, PROMOTER, RUN_A, RUN_B, fingerprint, key, policy
from tests.test_058_promote import Room, _codes

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

SKILL_A, SKILL_B = "sha256:" + "a1" * 32, "sha256:" + "b2" * 32
OPTIMIZER = "9e" * 32


def _record(folder, run: str, seed: str = PROMOTER, **artifacts: str) -> None:
    record(key(seed), run=run, artifacts=artifacts, store=folder, at=AT)


def _pin(store, runner: str = PROMOTER) -> None:
    """Pin ``runner`` as a ``runner`` key and the optimizer's key in ``store``."""
    store.mkdir(parents=True, exist_ok=True)
    roles = (f'version = 1\n[roles]\nrunner = ["{fingerprint(runner)}"]\n'
             f'optimizer = ["{fingerprint(OPTIMIZER)}"]\n')  # fmt: skip
    (store / "key-roles.toml").write_bytes(roles.encode())
    pin_roles(store)


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    room = Room(tmp_path)
    room.lineage = tmp_path / ".tine" / "lineage"
    _pin(tmp_path / ".tine")
    _record(room.lineage, RUN_B, code_tree="sha256:" + "1" * 64, skill=SKILL_B)
    return room


def _args(room: Room, capsys, run: str, label: str) -> list[str]:
    base = room.evals(f"base-{label}", RUN_A, lambda i: i % 2 == 0)
    cand = room.evals(f"cand-{label}-{run[-1]}", run, lambda i: i % 10 != 0)
    return ["--baseline-evals", base.as_posix(), "--evals", cand.as_posix(), "--approval",
            room.approve(capsys, run, label=label).as_posix(), "--spent", "1",
            "--lineage", room.lineage.as_posix()]  # fmt: skip


def test_the_skill_slot_is_a_lineage_artifact(tmp_path):
    from opentine._lineage_check import check, read_folder

    _record(tmp_path, RUN_A, skill=SKILL_A)
    [name] = [n for n in read_folder(tmp_path) if n.startswith("variants/")]
    claim = json.loads((tmp_path / name).read_bytes())["claim"]
    assert claim["artifacts"] == {"skill": SKILL_A}
    assert check(read_folder(tmp_path), claim["variant"], None)["ok"]


def test_a_skill_change_under_a_plain_label_is_shown_and_advisory(room, capsys):
    pol = policy(room.base, require_holdout=False)
    code, row = room.promote(capsys, RUN_B, *_args(room, capsys, RUN_B, "prod"), pol=pol)
    assert code == 0, row.get("refusals")
    assert row["skills"] == {"from": None, "to": SKILL_B, "label": "prod"}
    assert "advisory:promote.skill-changed" in {a["code"] for a in row["advisories"]}
    decision = json.loads((room.base / "out" / "decision.json").read_bytes())
    assert decision["claim"]["skills"] == row["skills"]


def test_a_required_rule_refuses_a_skill_change_under_a_plain_label(room, capsys):
    pol = policy(room.base, require_holdout=False, skill_labels="required")
    code, row = room.promote(capsys, RUN_B, *_args(room, capsys, RUN_B, "prod"), pol=pol)
    assert code == 1 and _codes(row) == {"promote.skill-label-required"}


def test_a_skill_label_promotes_and_reverts(room, capsys):
    pol = policy(room.base, require_holdout=False, skill_labels="required")
    label = "skill.search"
    code, row = room.promote(capsys, RUN_B, *_args(room, capsys, RUN_B, label), label=label,
                             pol=pol)  # fmt: skip
    assert code == 0, row.get("refusals")
    assert row["skills"]["label"] == label
    assert "advisory:promote.skill-changed" not in {a["code"] for a in row["advisories"]}
    code, row = room.promote(capsys, RUN_B, "--revert", "--reason", "regressed", label=label,
                             pol=pol, out="two")  # fmt: skip
    assert code == 0 and (row["action"], row["current"]) == ("revert", None)


def test_a_skill_label_on_a_candidate_with_no_skill_fails_closed(tmp_path):
    _record(tmp_path, RUN_A, code_tree="sha256:" + "1" * 64)
    rule = {"skill_labels": "required"}
    refused, _, _ = findings(rule, candidate=RUN_A, current=None, label="skill.x",
                             lineage=tmp_path, repo_path=None)  # fmt: skip
    assert [r["code"] for r in refused] == ["promote.skill-unrecorded"]
    quiet = findings({"skill_labels": "advisory"}, candidate=RUN_A, current=None,
                     label="skill.x", lineage=tmp_path, repo_path=None)  # fmt: skip
    assert quiet == ([], [], None)


def test_an_unsigned_record_does_not_count(tmp_path):
    _record(tmp_path, RUN_A, skill=SKILL_A)
    [path] = (tmp_path / "variants").iterdir()
    doc = json.loads(path.read_bytes())
    doc["claim"]["artifacts"]["skill"] = SKILL_B
    path.write_bytes(json.dumps(doc).encode())
    assert findings({"skill_labels": "advisory"}, candidate=RUN_A, current=None, label="prod",
                    lineage=tmp_path, repo_path=None) == ([], [], None)  # fmt: skip


def test_the_rsi_profile_requires_skill_labels():
    rsi = {"profile": "rsi"}
    check_policy(rsi)
    assert rsi["skill_labels"] == "required"
    with pytest.raises(ValueError):
        check_policy({"profile": "rsi", "skill_labels": "advisory"})
    plain: dict = {}
    check_policy(plain)
    assert plain["skill_labels"] == "advisory"


def _forged(tmp_path):
    """The current holder used SKILL_A; the optimizer signs RUN_B's record as SKILL_A too."""
    lineage = tmp_path / ".tine" / "lineage"
    _pin(tmp_path / ".tine")
    _record(lineage, RUN_A, skill=SKILL_A)
    _record(lineage, RUN_B, seed=OPTIMIZER, skill=SKILL_A, code_tree="sha256:" + "2" * 64)
    return lineage


def test_an_optimizer_signed_skill_digest_is_refused_under_rsi(tmp_path):
    lineage = _forged(tmp_path)
    rule = {"profile": "rsi"}
    check_policy(rule)
    refused, _, row = findings(rule, candidate=RUN_B, current=RUN_A, label="prod",
                               lineage=lineage, repo_path=None)  # fmt: skip
    assert [r["code"] for r in refused] == ["promote.skill-label-required"]
    assert row == {"from": SKILL_A, "to": "conflicting", "label": "prod"}
    refused, _, _ = findings(rule, candidate=RUN_B, current=RUN_A, label="skill.x",
                             lineage=lineage, repo_path=None)  # fmt: skip
    assert [r["code"] for r in refused] == ["promote.skill-unrecorded"]


def test_an_unpinned_record_signer_is_refused_under_a_required_rule(tmp_path):
    _record(tmp_path, RUN_A, skill=SKILL_A)  # no key roles pinned for this folder
    refused, _, _ = findings({"skill_labels": "required"}, candidate=RUN_A, current=None,
                             label="skill.x", lineage=tmp_path, repo_path=None)  # fmt: skip
    assert [r["code"] for r in refused] == ["promote.skill-unrecorded"]


def test_an_optimizer_signed_record_stays_advisory_outside_rsi(tmp_path):
    lineage = _forged(tmp_path)
    rule: dict = {}
    check_policy(rule)
    assert findings(rule, candidate=RUN_B, current=RUN_A, label="prod", lineage=lineage,
                    repo_path=None) == ([], [], None)  # fmt: skip
