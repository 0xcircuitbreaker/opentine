"""0.48: ``tine compliance list|check`` profiles and the Provenance Run Crate export."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from opentine import _compliance, _schemas, cli
from opentine._compliance_facts import FACTS
from opentine._run_crate_check import validate as validate_crate
from opentine.core import Run, RunStatus, StepKind

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "docs" / "compliance"
#: A citation names an article, rule or point number, never just a title.
_CITE = re.compile(r"(Art\. \d+|FRE \d{3}\(|Rule \d{3})")


def _tine(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    return code, capsys.readouterr().out


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="comp_run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.tool, {"q": 1}, outputs={"r": 2}, tool_info={"name": "bash"})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path


def test_every_profile_is_valid_cites_numbers_and_carries_the_draft_notice():
    names = sorted(p.stem for p in PROFILES.glob("*.yaml"))
    assert names == ["eidas", "eu-ai-act", "fre-902"]
    for path in PROFILES.glob("*.yaml"):
        profile = _compliance.parse(path.read_text("utf-8"), path.name)
        assert _schemas.validate(profile, "opentine-compliance-profile-1")[1] == []
        assert profile["notice"] == "draft — not legal advice, pending counsel review"
        assert profile["counsel_review"] == "outstanding"  # no sign-off is recorded yet
        assert profile["profile"] == path.stem
        for req in profile["requirements"]:
            assert _CITE.search(req["cite"]), (path.name, req["id"])


def test_profiles_cite_the_articles_the_roadmap_names():
    cites = " ".join(
        r["cite"] for name in ("fre-902", "eu-ai-act", "eidas")
        for r in _compliance.load(name)["requirements"]
    )  # fmt: skip
    for needed in ("FRE 902(13)", "FRE 902(14)", "Art. 12(1)", "Art. 19(1)", "Art. 26(6)",
                   "Art. 25(1)", "Art. 26(1)(d)", "Art. 41(1)", "Art. 45k(1)"):  # fmt: skip
        assert needed in cites


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(notice="final"),
        lambda p: p["requirements"][0].update(evidence=["no-such-fact"]),
        lambda p: p["requirements"][0].update(cite=""),
        lambda p: p["requirements"][0].update(scope="out"),
        lambda p: p["requirements"].append(dict(p["requirements"][0])),
    ],
)
def test_a_bad_profile_is_refused(mutate):
    profile = _compliance.load("eidas")
    mutate(profile)
    with pytest.raises(_compliance.ProfileError):
        _compliance.validate(profile)


def test_evaluate_is_pure_and_needs_every_listed_fact():
    profile = _compliance.load("eu-ai-act")
    facts = {f: {"status": "evidenced", "detail": "x"} for f in FACTS}
    body = _compliance.evaluate(profile, facts)
    assert body["summary"]["missing"] == 0
    facts["retention.six-months"] = {"status": "missing", "detail": "keep_days = 14"}
    rows = {r["id"]: r["status"] for r in _compliance.evaluate(profile, facts)["requirements"]}
    assert rows["art19.1.provider-retention"] == rows["art26.6.deployer-retention"] == "missing"
    assert rows["art12.1.automatic-logs"] == "evidenced"
    assert rows["art26.1-4.organisational"] == "out-of-scope"


def test_check_json_validates_and_reports_what_an_unsigned_run_lacks(room, monkeypatch, capsys):
    code, out = _tine(monkeypatch, capsys, "compliance", "check", "run.tine", "--profile",
                      "eidas", "--json")  # fmt: skip
    assert code == 0
    doc = json.loads(out)
    assert _schemas.validate_output(doc) == []
    assert doc["notice"].startswith("draft")
    assert doc["facts"]["integrity"]["status"] == "evidenced"
    assert doc["facts"]["signature"]["status"] == "missing"
    rows = {r["id"]: r["status"] for r in doc["requirements"]}
    assert rows["art25.1.electronic-signature"] == "missing"
    assert rows["qualified.services"] == "out-of-scope"


def test_strict_exits_4_and_text_output_carries_the_notice(room, monkeypatch, capsys):
    code, out = _tine(monkeypatch, capsys, "compliance", "check", "run.tine", "--profile",
                      "fre-902", "--strict")  # fmt: skip
    assert code == 4
    assert "not legal advice" in out


def test_a_signed_run_in_a_retaining_repo_evidences_signature_and_retention(
    room, monkeypatch, capsys
):
    assert _tine(monkeypatch, capsys, "keygen", "--out", "signer.key")[0] == 0
    pub = next(p for p in room.iterdir() if p.name.startswith("signer") and p.suffix == ".pub")
    code, _ = _tine(monkeypatch, capsys, "sign", "run.tine", "--algorithm", "ed25519",
                    "--ed25519-key-file", "signer.key", "--force")  # fmt: skip
    assert code == 0
    assert _tine(monkeypatch, capsys, "init", "repo")[0] == 0
    from opentine.repository import Repo

    (Path(Repo.open("repo").path) / "retention.toml").write_text("keep_days = 200\n", "utf-8")
    code, out = _tine(monkeypatch, capsys, "compliance", "check", "run.tine", "--profile",
                      "eidas", "--pubkey", pub.name, "--repo", "repo", "--json")  # fmt: skip
    doc = json.loads(out)
    assert doc["facts"]["signature.authenticated"]["status"] == "evidenced"
    assert doc["facts"]["retention.six-months"]["status"] == "evidenced"
    rows = {r["id"]: r["status"] for r in doc["requirements"]}
    assert rows["art26.a-b.advanced-identifies"] == "evidenced"
    assert rows["art26.d.advanced-change-detectable"] == "evidenced"


def test_list_json_and_an_unknown_profile(room, monkeypatch, capsys):
    code, out = _tine(monkeypatch, capsys, "compliance", "list", "--json")
    doc = json.loads(out)
    assert code == 0 and _schemas.validate_output(doc) == []
    assert [p["name"] for p in doc["profiles"]] == ["eidas", "eu-ai-act", "fre-902"]
    code, _ = _tine(monkeypatch, capsys, "compliance", "check", "run.tine", "--profile", "nope")
    assert code == 2


def test_run_crate_export_validates_against_the_provenance_profile(room, monkeypatch, capsys):
    code, out = _tine(monkeypatch, capsys, "export", "run.tine", "--format", "run-crate")
    assert code == 0
    crate = json.loads(out)
    assert validate_crate(crate) == []
    types = [e["@type"] for e in crate["@graph"]]
    assert types.count("ControlAction") == 2 and "OrganizeAction" in types
    again = _tine(monkeypatch, capsys, "export", "run.tine", "--format", "run-crate")[1]
    assert again == out  # deterministic: no clock, host or path


@pytest.mark.parametrize(
    "breakage",
    [
        lambda c: c["@context"].pop(),
        lambda c: c["@graph"][1]["conformsTo"].pop(2),
        lambda c: c["@graph"].pop(
            next(i for i, e in enumerate(c["@graph"]) if e["@type"] == "ControlAction")
        ),
        lambda c: c["@graph"].append({"@id": "#x", "@type": "Thing", "p": {"@id": "#gone"}}),
        lambda c: c["@graph"].pop(
            next(i for i, e in enumerate(c["@graph"]) if e["@type"] == "OrganizeAction")
        ),
    ],
)
def test_the_run_crate_validator_rejects_broken_crates(room, monkeypatch, capsys, breakage):
    crate = json.loads(_tine(monkeypatch, capsys, "export", "run.tine", "--format", "run-crate")[1])
    breakage(crate)
    assert validate_crate(crate)
