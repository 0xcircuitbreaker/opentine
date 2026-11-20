"""0.73: tine uplift suite|record|horizon|compare, held signed records, exact recompute."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, _uplift, _uplift_synth, cli
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import key
from tests.query_helpers import add_run, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SCORER, OTHER, OPTIMIZER = "5a" * 32, "22" * 32, "7c" * 32
AT = "2026-12-01T10:00:00Z"


def _fp(seed: str) -> str:
    return key_fingerprint(key(seed).public_key().public_bytes_raw())


def _key(room: dict, seed: str) -> str:
    return (room["base"] / f"{seed[:2]}.key").as_posix()


@pytest.fixture
def room(tmp_path: Path) -> dict:
    repo = Repo.init(tmp_path / "r")
    text = (f"version = 1\n[roles]\nscorer = {json.dumps([_fp(SCORER)])}\n"
            f"optimizer = {json.dumps([_fp(OPTIMIZER)])}\n")  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    for seed in (SCORER, OTHER, OPTIMIZER):
        (tmp_path / f"{seed[:2]}.key").write_bytes(seed.encode("ascii"))
    data = _uplift_synth.generate(5, tasks=8, attempts=4)
    suite = {
        "name": "toy",
        "version": "1",
        "scoring": "binary",
        "tasks": [{"id": t["id"], "minutes": str(t["minutes"])} for t in data["tasks"]],
    }
    (tmp_path / "suite.json").write_bytes(json.dumps(suite).encode("utf-8"))
    run = add_run(repo, "run0", cost=0.1)
    room = {"base": tmp_path, "repo": repo, "run": run, "data": data,
            "args": ("--repo", (tmp_path / "r").as_posix())}  # fmt: skip
    room["suite"] = _uplift.suite_digest(suite)
    _uplift.record(repo, run, {"convention": _uplift.SUITE, "digest": room["suite"],
                               "suite": suite, "at": AT}, key(SCORER))  # fmt: skip
    for i, (task, ok) in enumerate(data["attempts"]):
        claim = {
            "convention": _uplift.RECORD,
            "record": "run",
            "suite": room["suite"],
            "task": task,
            "subject": "model-a",
            "condition": "ai",
            "success": ok,
            "minutes": None,
            "perceived_minutes": None,
            "generation": i % 2,
            "at": AT,
        }
        _uplift.record(repo, run, claim, key(SCORER))
    return room


def _rec(capsys, room: dict, seed: str, *extra: str):
    return tine(capsys, "uplift", "record", "--suite", room["suite"], "--run", room["run"],
                "--key", _key(room, seed), "--at", AT, *room["args"], *extra)  # fmt: skip


def _raw(capsysbinary, *argv: str) -> tuple[int, bytes]:
    capsysbinary.readouterr()
    try:
        cli.main([*argv, "--json"])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsysbinary.readouterr().out


def test_horizon_from_repo_equals_recompute_from_export_byte_for_byte(room, capsysbinary):
    export = (room["base"] / "export.json").as_posix()
    code, live = _raw(capsysbinary, "uplift", "horizon", "--suite", room["suite"], "--seed", "4",
                      "--resamples", "60", "--export", export, *room["args"])  # fmt: skip
    body = json.loads(live)
    assert code == 0, body
    _schemas.validate(body, "tine-cli-uplift-1")
    assert body["fit"]["status"] == "ok" and body["seed"] == 4 and body["resamples"] == 60
    assert [t["generation"] for t in body["trend"]] == [0, 1]
    _schemas.validate(json.loads(Path(export).read_bytes()), "opentine-uplift-export-1")
    code2, again = _raw(capsysbinary, "uplift", "horizon", "--from", export, "--seed", "4",
                        "--resamples", "60")  # fmt: skip
    assert code2 == 0 and again == live


def test_records_compare_and_refusals(room, capsys):
    code, out = _rec(capsys, room, SCORER, "--type", "baseline", "--task", "t03",
                     "--subject", "alice", "--condition", "human", "--success", "yes",
                     "--minutes", "20")  # fmt: skip
    assert code == 0, out
    _schemas.validate(out, "tine-cli-uplift-1")
    assert _rec(capsys, room, SCORER, "--type", "speed", "--task", "t03", "--subject", "bob",
                "--condition", "ai-assisted", "--minutes", "30",
                "--perceived-minutes", "15")[0] == 0  # fmt: skip
    for cond, minutes in (("ai-assisted", "30"), ("unassisted", "25")):
        assert (
            _rec(
                capsys,
                room,
                SCORER,
                "--type",
                "run",
                "--task",
                "t03",
                "--subject",
                "bob",
                "--condition",
                cond,
                "--success",
                "yes",
                "--minutes",
                minutes,
            )[0]
            == 0
        )
    # an unpinned signer is recorded but does not count (advisory)
    assert _rec(capsys, room, OTHER, "--type", "run", "--task", "t01", "--subject", "x",
                "--condition", "ai", "--success", "no")[0] == 0  # fmt: skip
    # refusals: optimizer key, unknown task, a baseline that is not human
    assert _rec(capsys, room, OPTIMIZER, "--type", "run", "--task", "t01", "--subject", "x",
                "--condition", "ai", "--success", "no")[0] != 0  # fmt: skip
    assert _rec(capsys, room, SCORER, "--type", "run", "--task", "nope", "--subject", "x",
                "--condition", "ai", "--success", "no")[0] != 0  # fmt: skip
    assert _rec(capsys, room, SCORER, "--type", "baseline", "--task", "t01", "--subject", "x",
                "--condition", "ai", "--success", "no")[0] != 0  # fmt: skip
    code, out = tine(capsys, "uplift", "compare", "--suite", room["suite"], "--a", "unassisted",
                     "--b", "ai-assisted:bob", "--resamples", "5", *room["args"])  # fmt: skip
    assert code == 0, out
    _schemas.validate(out, "tine-cli-uplift-1")
    assert out["paired_tasks"] == 1 and out["b_over_a_minutes"] == "1.200000"
    assert out["b"]["perceived_over_measured"] == "0.500000"
    assert [f["code"] for f in out["findings"]] == ["advisory:uplift.signer-unpinned"]
    assert (
        tine(
            capsys,
            "uplift",
            "compare",
            "--suite",
            room["suite"],
            "--a",
            "unassisted",
            "--b",
            "ai",
            "--resamples",
            "5",
            "--strict",
            *room["args"],
        )[0]
        == 1
    )
    # a human-only horizon has too few points: refused, exit 1
    code, out = tine(capsys, "uplift", "horizon", "--suite", room["suite"], "--condition",
                     "human", "--resamples", "5", *room["args"])  # fmt: skip
    assert code == 1 and out["fit"]["status"] == "insufficient-data"
    assert "fail:uplift.fit-refused" in [f["code"] for f in out["findings"]]


def test_records_are_held_and_never_released(room):
    with pytest.raises(HoldError):
        release(room["repo"], _uplift.hold_target(room["suite"]))


def test_suite_digest_without_key_and_tampered_export(room, capsys):
    code, out = tine(capsys, "uplift", "suite", (room["base"] / "suite.json").as_posix())
    assert code == 0 and out["suite"] == room["suite"] and out["record"] is None
    code, out = tine(
        capsys,
        "uplift",
        "suite",
        (room["base"] / "suite.json").as_posix(),
        "--run",
        room["run"],
        "--key",
        _key(room, SCORER),
        *room["args"],
    )
    assert code == 0 and out["record"].startswith("attestation:"), out
    _schemas.validate(out, "tine-cli-uplift-1")
    export = room["base"] / "e.json"
    assert tine(capsys, "uplift", "horizon", "--suite", room["suite"], "--resamples", "5",
                "--export", export.as_posix(), *room["args"])[0] == 0  # fmt: skip
    doc = json.loads(export.read_bytes())
    doc["definition"]["tasks"][0]["minutes"] = "999"
    export.write_bytes(json.dumps(doc).encode("utf-8"))
    assert tine(capsys, "uplift", "horizon", "--from", export.as_posix())[0] != 0


def test_unknown_suite_is_refused(room, capsys):
    other = "sha256:" + "0" * 64
    assert tine(capsys, "uplift", "horizon", "--suite", other, *room["args"])[0] != 0
    assert (
        _rec(
            capsys,
            room,
            SCORER,
            "--type",
            "run",
            "--task",
            "t01",
            "--subject",
            "x",
            "--condition",
            "ai",
            "--success",
            "no",
            "--suite",
            other,
        )[0]
        != 0
    )
