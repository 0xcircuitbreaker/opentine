"""0.61: canaries with declared entropy, ``tine integrity scan`` and ``canary-check``.

A canary registration counts only when a pinned dataset-role key signs it. The
scan finds canaries in runs, prompts, memory and exported packs, and its
content-addressed index makes a repeat scan read only new objects (proven by
operation counts, not wall-clock time). ``canary-check`` refuses a model that
codes a canary below its declared entropy: a deterministic integer stub model
primed on the canary is refused, an unprimed one is not.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from opentine import Run, StepKind, cli
from opentine._canary import digest
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import AT, fingerprint

DATASET = "5d" * 32
OPTIMIZER = "0f" * 32
CANARY = "tine-canary 7f3a9c2e41d8b605e9a1c3f7"
OTHER = "tine-canary 0b5e7d19c4a2f8e63d71b0aa"
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _keyfile(base: Path, seed: str) -> str:
    path = base / f"{seed[:2]}.key"
    path.write_bytes(seed.encode("ascii"))
    return path.as_posix()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    Repo.init(root)
    roles = f'version = 1\n[roles]\ndataset = ["{fingerprint(DATASET)}"]\n'
    roles += f'optimizer = ["{fingerprint(OPTIMIZER)}"]\n'
    (root / ".tine" / "key-roles.toml").write_bytes(roles.encode("ascii"))
    pin_roles(root / ".tine")
    return root


def _register(capsys, root: Path, text: str, bits: int, seed: str = DATASET) -> dict:
    code, row = _cli(capsys, "dataset", "canary-add", text, "--entropy-bits", str(bits),
                     "--holdout", "h1", "--key", _keyfile(root.parent, seed), "--at", AT,
                     "--repo", root.as_posix(), "--json")  # fmt: skip
    assert code == 0, row
    return row["canary"]


def _scan(capsys, root: Path, *extra: str) -> tuple[int, dict]:
    return _cli(capsys, "integrity", "scan", "--repo", root.as_posix(), *extra, "--json")


def _run(text: str) -> Run:
    run = Run(id=f"r-{digest(text)[:12]}", model_info="mock", user_prompt=text)
    run.add_step(StepKind.done, {"text": "ok"})
    return run


def test_registration_counts_only_for_a_pinned_dataset_key(capsys, root: Path) -> None:
    row = _register(capsys, root, CANARY, 96)
    assert row["counted"] is True and row["canary_sha256"] == digest(CANARY)
    assert row["signer"] == fingerprint(DATASET)
    other = _register(capsys, root, OTHER, 96, seed=OPTIMIZER)
    assert other["counted"] is False
    code, listing = _cli(capsys, "dataset", "canary-list", "--repo", root.as_posix(), "--json")
    assert code == 0 and sorted(c["counted"] for c in listing["canaries"]) == [False, True]
    assert CANARY not in json.dumps(listing)  # outputs never repeat a canary


def test_bad_canaries_are_refused(capsys, root: Path) -> None:
    for text, bits in (("short", 8), (CANARY, 0), (CANARY, 8 * len(CANARY) + 1), ("a\nb" * 4, 8)):
        code, row = _cli(capsys, "dataset", "canary-add", text, "--entropy-bits", str(bits),
                         "--key", _keyfile(root.parent, DATASET), "--repo", root.as_posix(),
                         "--json")  # fmt: skip
        assert code != 0 and "error" in row


def test_scan_finds_canaries_in_runs_prompts_memory_and_packs(
    capsys, root: Path, monkeypatch
) -> None:
    repo = Repo.open(root)
    _register(capsys, root, CANARY, 96)
    run_id = repo.put_run(_run(f"please answer {CANARY} now")).run_id
    repo.put_run(_run("a clean prompt with nothing planted"))
    monkeypatch.chdir(root)
    key = _keyfile(root.parent, OPTIMIZER)
    code, _ = _cli(capsys, "prompt", "push", "demo", "--template", f"system: {CANARY}",
                   "--key", key, "--created-at", AT, "--json")  # fmt: skip
    assert code == 0
    code, _ = _cli(capsys, "memory", "add", "notes", f'remember "{CANARY}"', "--key", key,
                   "--created-at", AT, "--json")  # fmt: skip
    assert code == 0
    pack = root.parent / "export.bin"
    pack.write_bytes(b"\x00\x01" + CANARY.encode() + b"\xff")
    code, row = _scan(capsys, root, "--file", pack.as_posix())
    assert code == 1 and row["ok"] is False
    surfaces = {m["surface"] for m in row["matches"]}
    assert surfaces == {"runs", "prompts", "memory", "packs"}
    assert all(m["canary_sha256"] == digest(CANARY) and m["holdout"] == "h1"
               for m in row["matches"])  # fmt: skip
    assert run_id.startswith("run:")
    assert CANARY not in json.dumps(row)


def test_a_clean_repository_scans_clean(capsys, root: Path) -> None:
    Repo.open(root).put_run(_run("nothing to see"))
    _register(capsys, root, CANARY, 96)
    code, row = _scan(capsys, root)
    assert code == 0 and row["ok"] and row["matches"] == []


def _grow(repo: Repo, start: int, count: int) -> None:
    for i in range(start, start + count):
        repo.put("blob", f"filler object {i} without any planted string".encode())


@pytest.mark.parametrize("size", [40, 160])
def test_a_repeat_scan_reads_only_new_objects(capsys, root: Path, size: int) -> None:
    repo = Repo.open(root)
    _register(capsys, root, CANARY, 96)
    _grow(repo, 0, size)
    code, first = _scan(capsys, root)
    assert code == 0 and first["counts"]["read"] == first["counts"]["objects"] >= size
    repo.put("blob", f"leaked: {CANARY}".encode())
    code, second = _scan(capsys, root)
    counts = second["counts"]
    assert code == 1 and counts["read"] == 1 and counts["matches"] == 1
    assert counts["cached"] == first["counts"]["objects"]
    code, third = _scan(capsys, root)
    assert third["counts"]["read"] == 0 and third["counts"]["matches"] == 1
    _register(capsys, root, OTHER, 96)  # a new canary set rescans everything once
    code, fourth = _scan(capsys, root)
    assert fourth["counts"]["read"] == fourth["counts"]["objects"]


class StubModel:
    """A deterministic integer byte model: order-4 context counts, add-one smoothing.

    The code length of a byte is ``bitlen(total + 256) - bitlen(count + 1)``, an
    integer approximation of ``-log2((count + 1) / (total + 256))``. Unprimed, every
    byte costs 8 bits.
    """

    def __init__(self) -> None:
        self.counts: dict[bytes, dict[int, int]] = defaultdict(lambda: defaultdict(int))

    def train(self, text: str, times: int = 1) -> None:
        data = text.encode("utf-8")
        for _ in range(times):
            for i, byte in enumerate(data):
                self.counts[data[max(0, i - 4) : i]][byte] += 1

    def code_bits(self, text: str) -> int:
        data, bits = text.encode("utf-8"), 0
        for i, byte in enumerate(data):
            seen = self.counts.get(data[max(0, i - 4) : i], {})
            total, count = sum(seen.values()), seen.get(byte, 0)
            bits += (total + 256).bit_length() - (count + 1).bit_length()
        return bits


def _lengths(tmp: Path, model: StubModel, name: str) -> str:
    path = tmp / f"{name}.json"
    rows = [{"canary_sha256": digest(CANARY), "code_bits": model.code_bits(CANARY)}]
    path.write_bytes(json.dumps({"model": name, "lengths": rows}).encode("utf-8"))
    return path.as_posix()


def test_a_model_primed_on_the_canary_is_refused_and_an_unprimed_one_is_not(
    capsys, root: Path, tmp_path: Path
) -> None:
    declared = 4 * len(CANARY)  # well under the 8 bits/byte an unprimed model pays
    _register(capsys, root, CANARY, declared)
    unprimed = StubModel()
    unprimed.train("ordinary training text about tines and forks", times=20)
    primed = StubModel()
    primed.train(f"holdout row: {CANARY}", times=200)
    assert primed.code_bits(CANARY) < declared < unprimed.code_bits(CANARY)
    args = ("--repo", root.as_posix(), "--json")
    code, row = _cli(capsys, "dataset", "canary-check", _lengths(tmp_path, unprimed, "u"), *args)
    assert code == 0 and row["ok"] and row["judged"][0]["below"] is False
    code, row = _cli(capsys, "dataset", "canary-check", _lengths(tmp_path, primed, "p"), *args)
    assert code == 1 and row["ok"] is False
    assert [f["code"] for f in row["findings"]] == ["dataset.canary-below-entropy"]


def test_only_counted_canaries_judge_and_advisories_never_block(
    capsys, root: Path, tmp_path: Path
) -> None:
    _register(capsys, root, CANARY, 96)
    _register(capsys, root, OTHER, 200, seed=OPTIMIZER)  # not counted
    path = tmp_path / "l.json"
    scores = {digest(CANARY): 500, digest(OTHER): 1, "ab" * 32: 1}
    path.write_bytes(json.dumps(scores).encode("utf-8"))
    args = ("dataset", "canary-check", path.as_posix(), "--repo", root.as_posix(), "--json")
    code, row = _cli(capsys, *args)
    codes = sorted(f["code"] for f in row["findings"])
    assert code == 0 and row["ok"] and row["blocking"] == 0
    assert codes == ["dataset.canary-not-counted", "dataset.canary-unregistered"]
    code, row = _cli(capsys, *args, "--strict")
    assert code == 1 and row["blocking"] == 2


def test_a_malformed_lengths_file_is_an_error(capsys, root: Path, tmp_path: Path) -> None:
    for bad in ({"nothex": 1}, {"ab" * 32: -1}, {"ab" * 32: True}, []):
        path = tmp_path / "bad.json"
        path.write_bytes(json.dumps(bad).encode("utf-8"))
        code, row = _cli(capsys, "dataset", "canary-check", path.as_posix(), "--repo",
                         root.as_posix(), "--json")  # fmt: skip
        assert code != 0 and "error" in row
