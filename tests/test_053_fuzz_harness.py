"""0.53: the format-reader fuzz harness (1.0 criterion 1, the 72-hour run).

Every target seeds from the conformance vectors, a bounded run finds no crash,
the oracle tells a refusal from a crash, crash inputs land in the triage
directory and reproduce, triaged regressions replay cleanly, and CI runs it.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

from opentine import _fuzz, _fuzz_corpus
from opentine._fuzz_targets import TARGETS, Target

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_TARGETS = sorted(TARGETS)


def _script():
    import importlib.util

    spec = importlib.util.spec_from_file_location("fuzz_script", ROOT / "scripts" / "fuzz.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_targets_cover_every_reader_criterion_1_names():
    assert set(TARGETS) == {
        "otlp-spans", "otlp-logs", "tine", "pack", "localpack", "dsse", "inspect"}  # fmt: skip


@pytest.mark.parametrize("target", SCRIPT_TARGETS)
def test_every_target_seeds_from_the_vectors_and_some_seeds_read(target):
    seeds = _fuzz_corpus.seeds(target, ROOT)
    spec = TARGETS[target]
    assert seeds and all(len(parts) == spec.parts for parts in seeds)
    clean = [p for p in seeds if _fuzz.check(spec.run, (), p) is None]
    assert clean, f"{target}: no seed reads, so the fuzzer would only probe the first check"
    for parts in seeds:  # every seed reads or is refused, never crashes
        assert _fuzz.check(spec.run, spec.refusals, parts) is None


def test_the_corpus_reaches_every_pack_format_and_v5():
    packs = {parts[0][:10] for parts in _fuzz_corpus.seeds("pack", ROOT)}
    assert {b"TINEPACK3\0", b"TINEPACK4\0"} <= packs
    from opentine.repository import _pack5

    if _pack5.available():
        assert b"TINEPACK5\0" in packs
    tine = b"".join(parts[0] for parts in _fuzz_corpus.seeds("tine", ROOT))
    assert b"tine-artifact/4" in tine and b"tine-artifact/5" in tine
    dicts = [parts[2] for parts in _fuzz_corpus.seeds("localpack", ROOT)]
    assert any(len(d) > 2 for d in dicts), "the codec-3 dictionary vector is a seed"


@pytest.mark.parametrize("target", SCRIPT_TARGETS)
def test_a_bounded_run_finds_no_crash(target):
    seeds = _fuzz_corpus.seeds(target, ROOT)
    report = _fuzz.fuzz(target, seeds, seed=53, iterations=300)
    assert report.iterations == 300
    assert report.crashes == [], report.crashes[0]["trace"]


def test_the_oracle_tells_a_refusal_from_a_crash():
    def refuses(parts):
        raise ValueError("documented refusal")

    def crashes(parts):
        raise IndexError("unexpected")

    assert _fuzz.check(refuses, (ValueError,), (b"x",)) is None
    assert "IndexError" in _fuzz.check(crashes, (ValueError,), (b"x",))


def test_frames_round_trip_single_and_multi_part_inputs():
    for parts in [(b"",), (b"abc",), (b"a", b"", b"c" * 300), (b"TINEFUZZ1\0x",)]:
        assert _fuzz.unframe(_fuzz.frame(parts)) == parts
    assert _fuzz.frame((b"plain",)) == b"plain"


def test_crashes_land_in_the_triage_directory_and_reproduce(tmp_path, monkeypatch, capsys):
    def boom(parts):
        if parts[0][:1] == b"\x00":
            raise KeyError("boom")

    monkeypatch.setitem(TARGETS, "pack", Target(boom))
    monkeypatch.setattr(_fuzz_corpus, "seeds", lambda target, root: [(b"\x00",), (b"\x00a",)])
    script = _script()
    crashes = tmp_path / "crashes"
    code = script.main(["--target", "pack", "--iterations", "50", "--seed", "1",
                        "--crashes", str(crashes)])  # fmt: skip
    assert code == 1
    saved = sorted((crashes / "pack").glob("*.bin"))
    assert saved and all(p.with_suffix(".txt").is_file() for p in saved)
    assert "KeyError" in saved[0].with_suffix(".txt").read_text(encoding="utf-8")
    assert re.fullmatch(r"[0-9a-f]{16}\.bin", saved[0].name)
    assert script.reproduce(saved[0], None) == 1
    assert "KeyError" in capsys.readouterr().out


def test_the_long_mode_is_the_environment_variable(monkeypatch):
    script = _script()
    calls = []

    def fake(target, seeds, *, seed, iterations, seconds, on_crash, watch=None):
        calls.append((target, iterations, seconds))
        return _fuzz.Report(target, iterations=1)

    monkeypatch.setattr(script._fuzz, "fuzz", fake)
    monkeypatch.setattr(script._fuzz_corpus, "seeds", lambda target, root: [(b"",)])
    ticks = iter(range(0, 10**6, 400))
    monkeypatch.setattr(script.time, "monotonic", lambda: float(next(ticks)))
    monkeypatch.setenv(script.HOURS_ENV, "1")
    assert script.main(["--target", "pack", "--seed", "1", "--report-every", "600"]) == 0
    assert calls and all(it is None and secs <= 600 for _, it, secs in calls)
    monkeypatch.delenv(script.HOURS_ENV)
    with pytest.raises(SystemExit):
        script.main(["--seed", "1"])


@pytest.mark.parametrize("target", SCRIPT_TARGETS)
def test_triaged_regressions_now_read_or_refuse(target):
    spec = TARGETS[target]
    for parts in _fuzz_corpus.regressions(target, ROOT):
        assert _fuzz.check(spec.run, spec.refusals, parts) is None


def test_ci_runs_the_reader_fuzzer_bounded_and_the_docs_give_the_72h_command():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("\n  fuzz-otlp:\n", 1)[1].split("\n\n  peer-compat-034:", 1)[0]
    assert "scripts/fuzz.py --iterations" in job
    assert re.search(r"^    timeout-minutes: 30", job, re.M)
    assert "path: fuzz-crashes" in job
    releasing = (ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    assert "OPENTINE_FUZZ_HOURS=72" in releasing and "tests/fuzz_regressions/" in releasing
    assert _script().HOURS_ENV == "OPENTINE_FUZZ_HOURS"


def test_both_dsse_verifiers_reach_their_accept_path_from_a_seed():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _intoto_replay, intoto
    from opentine._fuzz_targets import DSSE_SEED_KEY

    public = Ed25519PrivateKey.from_private_bytes(DSSE_SEED_KEY).public_key()
    envelopes = [json.loads(p[0]) for p in _fuzz_corpus.seeds("dsse", ROOT)]
    assert any(intoto.verify_envelope(e, public_key=public).ok for e in envelopes)
    replayed = 0
    for envelope in envelopes:
        try:
            _intoto_replay.verify_envelope(envelope, public)
            replayed += 1
        except ValueError:
            pass
    assert replayed, "no seed gets past the replay/v1 signature check"


def test_the_dsse_oracle_catches_a_verifier_that_accepts_a_forgery(monkeypatch):
    from opentine import _intoto_replay

    envelopes = [json.loads(p[0]) for p in _fuzz_corpus.seeds("dsse", ROOT)]
    envelope = next(
        e
        for e in envelopes
        if isinstance(e.get("payload"), str) and b"replay/v1" in base64.b64decode(e["payload"])
    )
    envelope["signatures"][0]["sig"] = base64.b64encode(b"\0" * 64).decode()
    forged = (json.dumps(envelope).encode(),)
    spec = TARGETS["dsse"]
    assert _fuzz.check(spec.run, spec.refusals, forged) is None
    monkeypatch.setattr(_intoto_replay, "verify_envelope", lambda envelope, key: {})
    assert "did not sign" in _fuzz.check(spec.run, spec.refusals, forged)


def test_a_result_verifier_that_raises_valueerror_is_a_crash_not_a_refusal(monkeypatch):
    from opentine import intoto

    def raises(*args, **kwargs):
        raise ValueError("should have answered a result")

    monkeypatch.setattr(intoto, "verify_envelope", raises)
    spec = TARGETS["dsse"]
    seed = _fuzz_corpus.seeds("dsse", ROOT)[0]
    assert "AssertionError" in _fuzz.check(spec.run, spec.refusals, seed)


def test_a_truncated_frame_is_refused_not_an_indexerror():
    framed = _fuzz.frame((b"a", b"bcdef"))
    for cut in (framed[:-1], framed[:-5], framed + b"\x85"):  # mid-part, mid-length
        with pytest.raises(ValueError):
            _fuzz.unframe(cut)


def test_the_watchdog_saves_a_hung_input_and_exits(monkeypatch):
    script = _script()
    saved, exits = [], []
    monkeypatch.setattr(script.os, "_exit", lambda code: exits.append(code))
    watch = [None, None]
    stop = script.watchdog(watch, lambda t, p, why: saved.append((t, p, why)), lambda: "pack", 0.2)
    watch[:] = [script.time.monotonic() - 10.0, (b"stuck",)]
    deadline = script.time.monotonic() + 30.0
    while not exits and script.time.monotonic() < deadline:
        script.time.sleep(0.05)
    stop.set()
    watch[:] = [None, None]
    assert exits and exits[0] == 1
    assert saved[0][:2] == ("pack", (b"stuck",)) and saved[0][2].startswith("hang")


def test_fuzz_publishes_the_running_input_for_the_watchdog():
    seen = []

    def spy(parts):
        seen.append(list(watch))

    watch: list[object] = [None, None]
    original = TARGETS["pack"]
    TARGETS["pack"] = Target(spy)
    try:
        _fuzz.fuzz("pack", [(b"x",)], seed=1, iterations=3, watch=watch)
    finally:
        TARGETS["pack"] = original
    assert len(seen) == 3 and all(s[0] is not None and isinstance(s[1], tuple) for s in seen)
    assert watch == [None, None]
