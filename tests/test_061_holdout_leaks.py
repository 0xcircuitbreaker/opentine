"""0.61: eval.holdout-touched, canaries with a declared entropy, and the clear-text scanner.

Scaling is asserted with operation counts, never wall-clock time.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

import pytest

from opentine import Run, StepKind, _bundle
from opentine.repository import Repo
from tests.holdout_helpers import DATASET, EVAL, ITEMS, Hold, codes, tine
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.promote_helpers import AT

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
CANARY = "c4a7f19e0b2d4e6f8a1c3e5b7d9f0a2c"  # 32 hex digits: 128 bits
HEX = "0123456789abcdef"


@pytest.fixture
def hold(tmp_path: Path, capsys) -> Hold:
    made = Hold(tmp_path)
    assert made.seal(capsys, unseals=5, items=6)[0] == 0
    return made


def _run(hold: Hold, name: str, text: str) -> str:
    run = Run(id=name, user_prompt="solve the task")
    run.add_step(StepKind.think, {"text": text}, {"answer": "done"})
    return hold.repo.put_run(run).run_id


def _eval(hold: Hold, capsys, run: str) -> tuple[int, dict]:
    code, row = hold.unseal(capsys, run=run, out=f"{run[-6:]}.jsonl")
    assert code == 0
    outputs = hold.base / f"outputs-{run[-6:]}.jsonl"
    with open(outputs, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(json.dumps({"id": item["id"], "output": "x", "run": run}) + "\n"
                          for item in ITEMS)  # fmt: skip
    return tine(capsys, "eval", "run", row["out"], "--outputs", outputs.as_posix(),
                "--scorer", "exact", "--key",
                hold.keys[EVAL], "--out", (hold.base / f"eval-{run[-6:]}").as_posix(),
                "--run", run, "--holdout", hold.folder().as_posix(), "--repo",
                hold.root.as_posix(), "--created-at", AT, "--json")  # fmt: skip


def test_a_clean_run_is_scored(hold: Hold, capsys) -> None:
    code, row = _eval(hold, capsys, _run(hold, "clean", "I wrote a parser for dates."))
    assert code == 0 and row["ok"] is True and row["items"] == len(ITEMS), row


def test_a_planted_leak_is_refused(hold: Hold, capsys) -> None:
    leak = _run(hold, "leak", f"notes: {ITEMS[3]['expected']}")
    code, row = _eval(hold, capsys, leak)
    assert code == 1 and codes(row) == {"eval.holdout-touched"}
    assert "h-03 in clear" in row["refusals"][0]["detail"]
    assert not (hold.base / f"eval-{leak[-6:]}").exists()


def test_a_planted_paraphrase_leak_is_refused(hold: Hold, capsys) -> None:
    words = ITEMS[2]["input"].split()
    words[-1] = "seven"  # one word changed: 6 of 7 five-word shingles survive
    code, row = _eval(hold, capsys, _run(hold, "para", "scratch " + " ".join(words)))
    assert code == 1 and "5-gram containment" in row["refusals"][0]["detail"]
    assert "threshold 0.8" in row["refusals"][0]["detail"]


def test_an_optimizer_run_that_unsealed_items_is_refused(hold: Hold, capsys) -> None:
    sneaky = _run(hold, "opt", "nothing to see")
    assert hold.unseal(capsys, "--purpose", "other", run=sneaky, out="peek.jsonl")[0] == 0
    code, row = _eval(hold, capsys, sneaky)
    assert code == 1 and "non-eval access record" in row["refusals"][0]["detail"]


def _register(hold: Hold, capsys, bits: str = "128") -> str:
    code, row = tine(capsys, "dataset", "canary-add", CANARY, "--entropy-bits", bits,
                     "--holdout", "h", "--key", hold.keys[DATASET], "--repo",
                     hold.root.as_posix(), "--at", AT, "--json")  # fmt: skip
    assert code == 0 and row["canary"]["counted"], row
    return row["canary"]["canary_sha256"]


def _code_length(text: str, corpus: str) -> float:
    """Bits a bigram stub model (add-one smoothing over hex) spends on *text*."""
    pairs, firsts = Counter(zip(corpus, corpus[1:], strict=False)), Counter(corpus[:-1])
    bits = math.log2(len(HEX))
    for a, b in zip(text, text[1:], strict=False):
        bits -= math.log2((pairs[(a, b)] + 1) / (firsts[a] + len(HEX)))
    return bits


@pytest.mark.parametrize(("primed", "refused"), [(True, True), (False, False)])
def test_a_model_primed_on_the_holdout_is_refused(hold, capsys, primed, refused) -> None:
    digest = _register(hold, capsys)
    corpus = (CANARY * 20) if primed else ""
    lengths = hold.base / "lengths.json"
    lengths.write_bytes(json.dumps({digest: _code_length(CANARY, corpus)}).encode())
    code, row = tine(capsys, "dataset", "canary-check", lengths.as_posix(), "--repo",
                     hold.root.as_posix(), "--json")  # fmt: skip
    found = {f["code"] for f in row["findings"]}
    assert (code == 1) is refused and (found == {"dataset.canary-below-entropy"}) is refused
    assert row["judged"][0]["below"] is refused


def test_a_canary_planted_in_a_prompt_is_found_by_the_integrity_scan(hold, capsys):
    _register(hold, capsys)
    _run(hold, "work", "routine work")
    _run(hold, "plant", f"prompt with {CANARY} inside")
    code, row = tine(capsys, "integrity", "scan", "--repo", hold.root.as_posix(), "--json")
    assert code == 1 and row["counts"]["matches"] >= 1, row


def _texts(repo: Repo) -> bytes:
    return b"\n".join(repo.raw(oid) for oid in repo.iter_oids())


def _clear(data: bytes) -> list[str]:
    return [item["id"] for item in ITEMS
            if item["expected"].encode() in data or item["input"].encode() in data]  # fmt: skip


def test_holdout_items_never_appear_in_clear_in_a_pack_or_bundle(hold, tmp_path, capsys):
    assert hold.unseal(capsys, run="run-eval")[0] == 0  # released outside the repository
    _register(hold, capsys)
    for i in range(3):
        _run(hold, f"work-{i}", f"ordinary step {i}")
    hold.repo.update_ref("heads/main", _run(hold, "head", "the head run"), expected_old=None)
    files = b"".join(p.read_bytes() for p in hold.root.rglob("*") if p.is_file())
    pack = hold.repo.pack()
    unpacked = Repo.init(tmp_path / "unpacked")
    unpacked.import_pack(pack)
    bundled = Repo.init(tmp_path / "bundled")
    _bundle.unbundle(bundled, _bundle.create(hold.repo, ["heads/main"]), "src")
    for name, data in (
        ("files", files),
        ("objects", _texts(hold.repo)),
        ("pack", pack),
        ("pack objects", _texts(unpacked)),
        ("bundle", _texts(bundled)),
    ):
        assert _clear(data) == [], name
    control = _run(hold, "leak", ITEMS[0]["expected"])  # the scanner does see a leak
    assert control and _clear(_texts(hold.repo)) == ["h-00"]
