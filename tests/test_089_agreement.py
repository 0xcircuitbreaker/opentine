"""0.89: ``tine judge agreement`` / ``validate`` over a label queue, and the promote gate."""

from __future__ import annotations

import json

import pytest

from opentine import _judge_provenance, _lineage, _promote_judges, _schemas
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import ADMIN, OPT, R1, SC, outputs, provenance
from tests.promote_helpers import AT, RUN_B, key, write_key
from tests.test_058_promote import _tine
from tests.test_089_judge_agreement import _reveal, labelled, truth
from tests.test_089_promote_agreement import room as room  # noqa: F401
from tests.test_089_promote_agreement import validate

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _agree(room, capsys, *extra):
    return _tine(capsys, "judge", "agreement", "--queue", "q", "--resamples", "200", "--repo",
                 room.repo.as_posix(), "--json", *extra)  # fmt: skip


def test_agreement_cli_recomputes_from_the_queue(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, out = _agree(room, capsys, "--judge", provenance(room.base / "jp.json").as_posix())
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    judge = out["judges"][0]
    assert judge["floor_ok"] and judge["multi_rater"]["lower"] is not None
    assert out["ok"] == (out["human"]["floor_ok"] and judge["floor_ok"])


def test_agreement_without_a_reveal_is_not_ok(room, capsys):
    labelled(room.repo, n=4)
    code, out = _agree(room, capsys, "--strict")
    assert code == 1 and out["judges"] == []


@pytest.mark.parametrize(("signer", "why"), [(OPT, "judge.validation-signer"),
                                             (R1, "judge.validation-signer")])  # fmt: skip
def test_only_a_pinned_scorer_or_policy_key_validates(room, capsys, signer, why):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    write_key(room.base / "sc.key", signer)
    code, out = validate(room, capsys)  # rewrites sc.key with SC: sign with *signer* instead
    assert code == 0, out
    from opentine import _judge_validation
    from opentine.repo import Repo

    claim = out["claim"]
    with pytest.raises(_judge_validation.ValidationError, match=why):
        _judge_validation.validate(Repo.open(room.repo), claim["subject"], rubric=claim["rubric"],
                                   queue=claim["queue"], cases=claim["adversarial"],
                                   agreement=claim["agreement"], key=key(signer),
                                   at=AT)  # fmt: skip


def test_a_validation_binds_the_queue_and_is_held(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, out = validate(room, capsys)
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    claim = out["claim"]
    assert claim["queue"]["name"] == "q" and claim["adversarial"]["fooled"] == 0
    assert claim["agreement"]["floor_ok"]


def test_adversarial_outcomes_must_be_signed(room, capsys):
    from opentine._label_queue import digest

    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, out = validate(room, capsys)
    assert code == 0
    cases = [json.loads(x) for x in (room.base / "adv.jsonl").read_bytes().splitlines()]
    plain = room.base / "adv-out.jsonl"  # an unsigned file of the "right" labels
    plain.write_bytes(b"".join(json.dumps({"item_sha256": digest(c), "label": "bad"}).encode()
                               + b"\n" for c in cases))  # fmt: skip
    code, out = _tine(capsys, "judge", "validate", "--queue", "q", "--judge",
                      (room.base / "jp.json").as_posix(), "--adversarial",
                      (room.base / "adv.jsonl").as_posix(), "--adversarial-outcomes",
                      plain.as_posix(), "--key", (room.base / "sc.key").as_posix(),
                      "--resamples", "200", "--repo", room.repo.as_posix(), "--json")  # fmt: skip
    assert code == 1 and "errored" in out["error"]["message"]
    outputs(plain, [{"item_sha256": digest(c), "label": "bad"} for c in cases], signer=OPT)
    code, out = _tine(capsys, "judge", "validate", "--queue", "q", "--judge",
                      (room.base / "jp.json").as_posix(), "--adversarial",
                      (room.base / "adv.jsonl").as_posix(), "--adversarial-outcomes",
                      plain.as_posix(), "--key", (room.base / "sc.key").as_posix(),
                      "--resamples", "200", "--repo", room.repo.as_posix(), "--json")  # fmt: skip
    assert code == 1 and "errored" in out["error"]["message"]


def _eval_folder(base, doc, name="ev", pin=None):
    folder = base / name
    folder.mkdir()
    (folder / "judge.json").write_bytes(json.dumps(doc).encode("utf-8"))
    rows = [{"item": "i0", "scorer": "llm-judge",
             "scorer_version": pin or _judge_provenance.pin(doc)}]  # fmt: skip
    (folder / "verdicts.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode())
    return folder


def test_promote_gate_is_advisory_by_default_and_refuses_under_rsi(room, capsys):
    doc = json.loads(provenance(room.base / "jp.json").read_bytes())
    folder = _eval_folder(room.base, doc)
    plain = {}
    _promote_judges.check_policy(plain)
    assert plain["judge_assurance"] == "advisory"
    held, told = _promote_judges.findings(plain, room.repo, RUN_B, None, {"evals": folder})
    assert held == [] and "advisory:judge.unvalidated" in {a["code"] for a in told}
    rsi = {"profile": "rsi"}
    _promote_judges.check_policy(rsi)
    held, _ = _promote_judges.findings(rsi, room.repo, RUN_B, None, {"evals": folder})
    assert {r["code"] for r in held} == {"promote.judge-unvalidated", "promote.judge-agreement"}
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    assert validate(room, capsys)[0] == 0
    rsi["resamples"] = 200
    assert _promote_judges.findings(rsi, room.repo, RUN_B, None, {"evals": folder}) == ([], [])
    (folder / "judge.json").unlink()  # deleting the judge's provenance does not skip the gate
    held, _ = _promote_judges.findings(rsi, room.repo, RUN_B, None, {"evals": folder})
    assert [r["code"] for r in held] == ["promote.judge-unvalidated"]
    other = _judge_provenance.build("local:judge", "Judge it generously", rubric="r")
    swapped = _eval_folder(room.base, other, "ev3")  # another judge, same model
    held, _ = _promote_judges.findings(rsi, room.repo, RUN_B, None, {"evals": swapped})
    assert {r["code"] for r in held} == {"promote.judge-unvalidated", "promote.judge-agreement"}


def test_the_retired_policy_keys_are_unknown(tmp_path):
    from opentine._promote_checks import _KEYS

    assert {"judge_floor", "judge_agreement"} & _KEYS == set()
    assert {"judge_assurance", "agreement_floor", "agreement_min_items",
            "agreement_min_coverage"} <= _KEYS  # fmt: skip


def test_an_unknown_candidate_is_not_independent(room, capsys):
    doc = json.loads(provenance(room.base / "jp.json").read_bytes())
    folder = _eval_folder(room.base, doc)
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    assert validate(room, capsys)[0] == 0
    rsi = {"profile": "rsi", "resamples": 200}
    _promote_judges.check_policy(rsi)
    held, _ = _promote_judges.findings(rsi, room.repo, "run:sha256:" + "e" * 64, None,
                                       {"evals": folder})  # fmt: skip
    assert [r["code"] for r in held] == ["promote.judge-not-independent"]
    _lineage.record(key("3d" * 32), run="run:sha256:" + "e" * 64,
                    artifacts={"prompt": doc["prompt_digest"]},
                    store=room.repo / ".tine" / "lineage", parents=[], at=AT)  # fmt: skip
    held, _ = _promote_judges.findings(rsi, room.repo, "run:sha256:" + "e" * 64, None,
                                       {"evals": folder})  # fmt: skip
    assert [r["code"] for r in held] == ["promote.judge-not-independent"]  # the family's prompt


__all__ = ["ADMIN", "SC"]
