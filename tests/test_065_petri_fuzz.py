"""0.65: the Petri/Bloom reader refuses hostile input with PetriError, never a crash."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from opentine import _petri

FIXTURES = Path(__file__).parent / "fixtures" / "petri"


def _read(data: bytes) -> None:
    try:
        doc = _petri.load(data)
    except _petri.PetriError:
        return
    _petri.to_run(doc)


@pytest.mark.parametrize("name", ["transcript.json", "bloom.json"])
def test_mutated_transcripts_import_or_refuse(name):
    seed = (FIXTURES / name).read_bytes()
    rng = random.Random(65)
    for _ in range(300):
        data = bytearray(seed)
        for _ in range(rng.randrange(1, 8)):
            at = rng.randrange(len(data))
            op = rng.randrange(3)
            if op == 0:
                data[at] = rng.randrange(256)
            elif op == 1:
                del data[at : at + rng.randrange(1, 16)]
            else:
                data[at:at] = bytes(rng.choice(b'{}[]",:0') for _ in range(rng.randrange(1, 8)))
        _read(bytes(data))


def test_structural_bombs_and_odd_shapes_are_bounded():
    with pytest.raises(_petri.PetriError):
        _petri.load(b"[" * 100_000 + b"]" * 100_000)
    with pytest.raises(_petri.PetriError):
        _petri.load(b" " * (_petri.MAX_BYTES + 1))
    with pytest.raises(_petri.PetriError):
        _petri.load(b"[]")
    many = {"metadata": {}, "messages": [{"role": "user"}] * (_petri.MAX_MESSAGES + 1)}
    with pytest.raises(_petri.PetriError):
        _petri.to_run(_petri.load(json.dumps(many).encode()))
    odd = {"metadata": {"judge_output": {"scores": {"x": True, "y": "1", "z": 2}}},
           "events": [None, 1, {"edit": {"message": {"content": [{"text": 5}, 7]}}}]}  # fmt: skip
    _petri.to_run(_petri.load(b'{"metadata": {"judge_output": 3}, "events": 5, "messages": 1}'))
    run = _petri.to_run(_petri.load(json.dumps(odd).encode()))
    assert run.steps[-1].outputs["scores"] == {"z": 2}
