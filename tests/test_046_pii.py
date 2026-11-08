"""0.46 ``opentine-redaction/3``: PII detectors, the classifier layer, version 2 reports."""

from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

import pytest

from opentine import _pii, _pii_classify, _pii_ids, _pii_report, _push_gate, cli
from opentine._pii_eval import evaluate, load, table
from opentine._redact_report import ReportError, check
from opentine._schemas import validate
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "pii" / "corpus.jsonl"
HMAC = b"k" * 32


def _kinds(text: str, classifier=None) -> list[tuple[str, str]]:
    return [(hit.kind, text[hit.start : hit.end]) for hit in _pii.find(text, classifier)]


@pytest.mark.parametrize(
    ("check_fn", "good", "bad"),
    [
        (_pii_ids.card, "4111-1111-1111-1111", "4111 1111 1111 1112"),
        (_pii_ids.card, "378282246310005", "0000000000000000"),
        (_pii_ids.iban, "GB82 WEST 1234 5698 7654 32", "GB83 WEST 1234 5698 7654 32"),
        (_pii_ids.iban, "NO9386011117947", "NO93860111179470"),  # wrong length for NO
        (_pii_ids.us_ssn, "219-09-9999", "666-12-3456"),
        (_pii_ids.us_ssn, "536-90-4399", "123-45-6789"),  # a published sample
        (_pii_ids.uk_nino, "JG103259A", "QQ123456C"),
        (_pii_ids.es_dni, "X1234567L", "12345678A"),
        (_pii_ids.phone, "+1 (415) 555-2671", "2026-11-08 12"),
        (_pii_ids.email, "a.b@example.org", "a..b@example.org"),
    ],
)
def test_validators_accept_the_real_shape_and_refuse_the_lookalike(check_fn, good, bad):
    assert check_fn(good) and not check_fn(bad)


def test_detectors_find_and_redact_without_touching_ids_and_dates():
    text = (
        "Reach jane@example.com, +44 20 7946 0958, card 4111 1111 1111 1111; "
        "built 2026-11-08 12:00:01 as run:sha256:4f2a v1.2.3 port 8080"
    )
    assert _kinds(text) == [
        ("email", "jane@example.com"),
        ("phone", "+44 20 7946 0958"),
        ("card", "4111 1111 1111 1111"),
    ]
    redacted, counts = _pii.redact_text(text)
    assert "jane@" not in redacted and "[REDACTED:card]" in redacted
    assert "2026-11-08 12:00:01" in redacted and counts == {"email": 1, "phone": 1, "card": 1}


def test_a_card_is_not_also_a_phone_number():
    assert [kind for kind, _ in _kinds("pay 5555 5555 5555 4444 now")] == ["card"]


def test_rule_classifier_finds_names_and_birth_dates():
    text = "Dear Dr. Alan Turing, DOB: 23/06/1912."
    found = _kinds(text, _pii_classify.RuleClassifier())
    assert found == [("classifier:person", "Alan Turing"), ("classifier:dob", "23/06/1912")]


def test_classifier_specs_are_local_only(monkeypatch):
    assert _pii_classify.load("none") is None
    assert _pii_classify.load(None).name == "rules/1"
    monkeypatch.setenv(_pii_classify.ENV, "none")
    assert _pii_classify.load(None) is None
    for spec in ("https://pii.example.invalid/classify", "http://x:y", "not a spec"):
        with pytest.raises(ValueError, match="locally"):
            _pii_classify.load(spec)


def test_a_plugged_in_classifier_is_used(monkeypatch):
    module = types.ModuleType("fake_pii_model")

    class Model:
        name = "fake/1"

        def classify(self, text):
            start = text.find("Zed")
            return [(start, start + 3, "person")] if start >= 0 else []

    module.Model = Model
    monkeypatch.setitem(sys.modules, "fake_pii_model", module)
    classifier = _pii_classify.load("fake_pii_model:Model")
    assert _pii_classify.name_of(classifier) == "fake/1"
    assert _kinds("hello Zed", classifier) == [("classifier:person", "Zed")]
    module.Broken = object()
    with pytest.raises(ValueError, match="classify"):
        _pii_classify.load("fake_pii_model:Broken")


def test_published_recall_and_precision_match_the_code():
    lines = load(CORPUS)
    published = (ROOT / "docs" / "PII.md").read_text("utf-8")
    block = re.search(r"<!-- pii-eval:begin -->\n(.*?)\n<!-- pii-eval:end -->", published, re.S)
    assert block and block.group(1) == table(lines, _pii_classify.RuleClassifier())
    counts = evaluate(lines, _pii_classify.RuleClassifier())
    tp, fp, fn = (sum(counts[k].values()) for k in ("tp", "fp", "fn"))
    assert tp / (tp + fp) >= 0.9 and tp / (tp + fn) >= 0.9  # the regression floor


def _repo(tmp_path, text: str) -> Repo:
    run = Run(id="r", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": text})
    repo = Repo.init(tmp_path / "store")
    repo.put_run(run, ref="heads/main")
    return repo


def test_version_2_report_names_detectors_never_values(tmp_path):
    repo = _repo(tmp_path, "mail jane@example.com, SSN 219-09-9999")
    run = repo.read_ref("heads/main")
    report = _pii_report.run_report(repo, run, _pii_classify.RuleClassifier())
    assert report["report_version"] == 2 and report["ruleset"] == "opentine-redaction/3"
    assert report["classifier"] == "rules/1" and not report["clean"]
    detectors = {name for hit in report["findings"] for name in hit["detectors"]}
    assert {"email", "gov-id:us-ssn"} <= detectors
    assert "jane@" not in json.dumps(report) and "219-09" not in json.dumps(report)
    signed = _push_gate.sign(report, HMAC, algorithm="hmac-sha256")
    assert check(signed, hmac_key=HMAC)["findings"] == len(report["findings"])
    assert validate(signed) == ("opentine-redaction-report-2", [])
    assert validate(_push_gate.run_report(repo, run))[0] == "opentine-redaction-report-1"


def test_version_signatures_do_not_cross(tmp_path):
    repo = _repo(tmp_path, "nothing personal here")
    run = repo.read_ref("heads/main")
    v2 = _push_gate.sign(_pii_report.run_report(repo, run), HMAC, algorithm="hmac-sha256")
    assert v2["clean"] and check(v2, hmac_key=HMAC)["clean"]
    v1 = _push_gate.sign(_push_gate.run_report(repo, run), HMAC, algorithm="hmac-sha256")
    forged = {**v2, "signature": v1["signature"]}
    with pytest.raises(ReportError) as info:
        check(forged, hmac_key=HMAC)
    assert info.value.code == "redaction-report.bad-signature"


def test_redact_check_pii_cli(tmp_path, capsys):
    repo = _repo(tmp_path, "call +1 415 555 0123")
    with pytest.raises(SystemExit) as info:
        cli.main(["redact", "check", "--repo", str(repo.path), "--pii", "--json"])
    assert info.value.code == 4
    out = json.loads(capsys.readouterr().out)
    assert out["reports"][0]["report_version"] == 2
    assert validate(out) == ("tine-cli-redact-check-1", [])
    cli.main(["redact", "check", "--repo", str(repo.path), "--json"])  # v1: no secrets, clean
    assert json.loads(capsys.readouterr().out)["clean"] is True


def test_redact_check_pii_classifier_none_and_errors(tmp_path, capsys):
    repo = _repo(tmp_path, "My name is Jane Doe")
    cli.main(["redact", "check", "--repo", str(repo.path), "--pii", "--classifier", "none",
              "--json"])  # fmt: skip
    out = json.loads(capsys.readouterr().out)
    assert out["clean"] and out["reports"][0]["classifier"] == "none"
    with pytest.raises(SystemExit) as info:
        cli.main(["redact", "check", "--repo", str(repo.path), "--classifier", "none"])
    assert info.value.code != 0


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_61_family_agrees_in_python_and_the_pyz(verifier):
    from opentine._pyz import _redactr
    from tests.conformance import tagged

    run, refused = (check, ReportError) if verifier == "python" else (
        _redactr.verify, _redactr.Refused)  # fmt: skip
    family = ROOT / "docs" / "conformance" / "vectors" / "62-redaction-report-v2.json"
    cases = json.loads(family.read_text("utf-8"))["cases"]
    assert len(cases) == 12
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        hmac, public = value["hmac_key_hex"], value["public_key"]
        keys = {
            "hmac_key": bytes.fromhex(hmac) if hmac else None,
            "public_key": bytes.fromhex(public) if public else None,
        }
        if case["expect"] == "accept":
            assert run(value["report"], **keys) == case["output"], case["id"]
        else:
            with pytest.raises(refused) as caught:
                run(value["report"], **keys)
            assert caught.value.code == case["reason"], case["id"]
