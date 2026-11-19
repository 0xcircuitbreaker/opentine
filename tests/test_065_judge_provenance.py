"""0.65: judge provenance is pinned by every signed llm-judge verdict."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine import _eval_judge, _judge_provenance
from opentine._eval_run import read_verdicts, verify_eval
from opentine.signing import generate_ed25519

pytestmark = pytest.mark.filterwarnings("ignore:.*plaintext-hex private key")


class _Fake:
    async def complete(self, messages, **_):
        assert "Rubric:\nFull marks" in messages[0]["content"]
        return {"text": "fine\nSCORE: 1"}


@pytest.fixture
def judged(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    seed, _ = generate_ed25519()
    (tmp_path / "k.key").write_bytes(seed.encode("utf-8"))
    (tmp_path / "rubric.md").write_bytes(b"Full marks only for the exact number.\n")
    rows = [{"id": f"i{n}", "input": "2+2", "expected": "4", "output": "4", "run": "run:x"}
            for n in range(2)]  # fmt: skip
    (tmp_path / "d.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode())
    monkeypatch.setattr(_eval_judge, "_model", lambda spec: _Fake())
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / "runs")
    try:
        cli.main(["eval", "run", "d.jsonl", "--scorer", "llm-judge:ollama:tiny", "--key",
                  "k.key", "--out", "ev", "--judge-rubric", "rubric.md"])  # fmt: skip
    except SystemExit as exc:
        assert not exc.code
    return tmp_path / "ev"


def test_the_signed_scorer_version_pins_model_prompt_rubric_and_sampling(judged):
    doc = json.loads((judged / "judge.json").read_bytes())
    assert doc["model"] == "ollama:tiny" and doc["sampling"] == {"temperature": "0"}
    rubric = "Full marks only for the exact number.\n"
    assert doc["rubric_digest"] == _judge_provenance.text_digest(rubric)
    assert doc["prompt_digest"] == _judge_provenance.text_digest(_eval_judge.DEFAULT_PROMPT)
    versions = {v["scorer_version"] for v in read_verdicts(judged)}
    assert versions == {_judge_provenance.pin(doc)}
    assert verify_eval(judged)["ok"]


def test_an_altered_rubric_digest_fails_digest_verification(judged):
    doc = json.loads((judged / "judge.json").read_bytes())
    doc["rubric_digest"] = "sha256:" + "0" * 64
    (judged / "judge.json").write_bytes(json.dumps(doc).encode("utf-8"))
    row = verify_eval(judged)
    assert not row["ok"] and row["failures"][0]["reason"] == "eval.summary-mismatch"


def test_rewriting_the_verdict_to_match_breaks_its_signature(judged):
    doc = json.loads((judged / "judge.json").read_bytes())
    doc["rubric_digest"] = "sha256:" + "0" * 64
    (judged / "judge.json").write_bytes(json.dumps(doc).encode("utf-8"))
    lines = []
    for verdict in read_verdicts(judged):
        verdict["scorer_version"] = _judge_provenance.pin(doc)
        lines.append(json.dumps(verdict, sort_keys=True) + "\n")
    (judged / "verdicts.jsonl").write_bytes("".join(lines).encode("utf-8"))
    reasons = {f["reason"] for f in verify_eval(judged)["failures"]}
    assert "eval-verdict.bad-signature" in reasons


def test_provenance_documents_are_checked():
    doc = _judge_provenance.build("m", "p", sampling={"top_p": 0.5})
    assert doc["sampling"] == {"temperature": "0", "top_p": "0.5"}
    assert doc["rubric_digest"] is None
    assert _judge_provenance.check({**doc, "extra": 1}) == ["unknown fields"]
    assert not _judge_provenance.matches({**doc, "model": ""}, _judge_provenance.pin(doc))
    with pytest.raises(ValueError):
        _judge_provenance.build("m", "p", sampling={"Bad Name": 1})


def test_deleting_the_judge_provenance_fails_verification(judged):
    (judged / "judge.json").unlink()
    row = verify_eval(judged)
    assert not row["ok"] and row["failures"][0]["reason"] == "eval.summary-mismatch"
