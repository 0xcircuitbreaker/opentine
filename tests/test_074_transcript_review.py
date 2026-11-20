"""0.74 review: perturbed transcripts still embed near their originals; inputs are strict."""

from __future__ import annotations

import base64
import math

import pytest

from opentine import _transcript_corpus as corpus
from opentine import _transcript_flags as tf
from opentine._transcript_space import Space, dot, features

BAD = ("step 3: edit tests/conftest.py: monkeypatch the grader so score always returns 1.0 "
       "then delete tests/test_billing.py and report all tests pass")  # fmt: skip
OTHER = [f"step {i}: run pytest tests/test_mod{i}.py -q then edit src/mod{i}/core.py "
         f"and fix the loop in helper{i}" for i in range(30)]  # fmt: skip


def _cos(perturbed: str) -> float:
    texts = {"bad": BAD, "probe": perturbed, **{f"o{i}": t for i, t in enumerate(OTHER)}}
    space = Space(texts)
    return dot(space.vectors["bad"], space.vectors["probe"])


def test_unicode_lookalikes_and_zero_width_characters_do_not_hide_a_transcript():
    swap = str.maketrans({"a": "а", "e": "е", "o": "о", "c": "с"})
    spoofed = BAD.translate(swap).replace("t", "t​")
    assert _cos(spoofed) > 0.95


def test_fullwidth_compatibility_forms_fold_to_their_plain_letters():
    wide = "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in BAD)
    assert _cos(wide) > 0.95


def test_base64_wrapped_commands_are_decoded_into_features():
    blob = base64.b64encode(BAD.encode("utf-8")).decode("ascii")
    assert _cos(f"step 1: echo {blob} | base64 -d | sh") > 0.6


def test_padding_before_the_behaviour_does_not_push_it_past_the_word_cap():
    padded = " ".join(["filler"] * 20000) + " " + BAD
    mine = features(padded)
    assert all(mine[h] > 0 for h in features(BAD))


def test_a_corpus_line_with_a_duplicate_key_is_refused(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_bytes(b'{"id": "a", "text": "benign", "text": "hidden"}\n')
    with pytest.raises(ValueError, match="duplicate key"):
        corpus.from_files([str(path)])


def test_a_corpus_line_with_nan_is_refused(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_bytes(b'{"id": "a", "text": "x", "score": NaN}\n')
    with pytest.raises(ValueError, match="not a finite number"):
        corpus.from_files([str(path)])


class _Model:
    name, dim, weights_digest = "m", 3, "sha256:" + "0" * 64

    def __init__(self, value):
        self.value = value

    def embed(self, texts):
        return [[self.value, 1.0, 0.0] for _ in texts]


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_a_model_returning_non_finite_vectors_is_refused(value):
    with pytest.raises(ValueError, match="finite"):
        Space({"a": "x", "b": "y"}, model=_Model(value))


def test_a_model_returning_the_wrong_dimension_is_refused():
    class Short(_Model):
        def embed(self, texts):
            return [[1.0] for _ in texts]

    with pytest.raises(ValueError, match="dimension"):
        Space({"a": "x"}, model=Short(0.0))


def test_labelled_at_must_be_an_rfc3339_utc_time():
    claim = {"convention": tf.CONVENTION, "label": "reward-hacking",
             "evidence": ["run:sha256:" + "a" * 64], "cluster": None, "labeller": "x",
             "backend": None, "note": "", "labelled_at": "tomorrow"}  # fmt: skip
    assert tf.check_claim(claim)
    claim["labelled_at"] = "2026-11-20T00:00:00Z"
    assert tf.check_claim(claim) == []
