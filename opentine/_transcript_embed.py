"""Embedding backends for the transcript index (0.74, release 0.73.0).

Every backend is identified by a ``backend_digest``: the sha256 of the
canonical JSON of its description. An index records the digest it was built
with; a different digest makes it stale, so vectors from two backends are
never compared.

``transcript-hash/1`` (the default) is standard library only and deterministic
across machines and processes. Features of the text normalised by
:mod:`opentine._transcript_norm` (lookalikes, zero-width characters, base64):

* word tokens (``\\w+``, at most ``MAX_TOKENS``) and word bigrams;
* character 4-grams of the first ``CHAR_SPAN`` characters, at half weight.

Each distinct feature has weight ``w * (1 + ln(count))`` and is hashed with
CRC-32 under two seeds; each hash picks one of ``DIM`` dimensions and a sign
(a sparse random projection). The vector is L2-normalised, so the dot product
of two vectors is their cosine similarity.

``MODULE:ATTR`` names a local model adapter (:mod:`opentine.repository._embed`):
an object with ``name``, ``dim``, ``embed(texts)`` and ``weights_path``, a
local file. The sha256 of that file is the ``weights_digest`` and part of the
description; a model whose weights are not a readable local file is refused,
and nothing is downloaded. ``weights_pin`` refuses weights with another digest.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import zlib
from collections import Counter
from pathlib import Path
from typing import Any

from opentine._transcript_norm import RULES, normalise

NAME = "transcript-hash/1"
DIM = 512
SEEDS = (0x6F70656E, 0x74696E65)
MAX_TOKENS = 20000
CHAR_SPAN = 4096
CHAR_N = 4
CHAR_WEIGHT = 0.5
_WORD = re.compile(r"\w+")
_STEP = re.compile(r"(?m)^(?=step \d+ )")
_SEQ = re.compile(r"^step \d+ ")


def digest_of(description: dict[str, Any]) -> str:
    raw = json.dumps(description, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _features(text: str) -> Counter:
    folded = normalise(text)
    words = _WORD.findall(folded)[:MAX_TOKENS]
    feats: Counter = Counter("w " + w for w in words)
    feats.update("b " + a + " " + b for a, b in zip(words, words[1:]))
    span = " ".join(_WORD.findall(folded[:CHAR_SPAN]))
    feats.update("c " + span[i : i + CHAR_N] for i in range(len(span) - CHAR_N + 1))
    return feats


def _unit(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(v * v for v in vector))
    return [v / norm for v in vector] if norm else vector


class HashBackend:
    """``transcript-hash/1``: hashed token, bigram and 4-gram features, random projection."""

    name = NAME
    dim = DIM

    def description(self) -> dict[str, Any]:
        return {"name": NAME, "dim": DIM, "seeds": list(SEEDS), "hash": "crc32",
                "features": {"tokens": MAX_TOKENS, "bigrams": True, "char_n": CHAR_N,
                             "char_span": CHAR_SPAN, "char_weight": CHAR_WEIGHT},
                "normalise": RULES, "weighting": "1+ln(count)",
                "segments": "per step, each unit length",
                "norm": "l2"}  # fmt: skip

    def segment(self, text: str) -> list[float]:
        vector = [0.0] * DIM
        for feat, count in _features(text).items():
            weight = (CHAR_WEIGHT if feat[0] == "c" else 1.0) * (1.0 + math.log(count))
            raw = feat.encode("utf-8")
            for seed in SEEDS:
                h = zlib.crc32(raw, seed)
                vector[h % DIM] += weight if h & 0x80000000 else -weight
        return _unit(vector)

    def one(self, text: str) -> list[float]:
        total = [0.0] * DIM
        for piece in _STEP.split(text):
            piece = _SEQ.sub("", piece, count=1)
            if piece.strip():
                total = [a + b for a, b in zip(total, self.segment(piece), strict=True)]
        return _unit(total)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self.one(t) for t in texts]


class ModelBackend:
    """A local model adapter with a recorded weights digest."""

    def __init__(self, spec: str, weights_pin: str | None = None) -> None:
        from opentine.repository._embed import load

        if spec in {"hash", "hash-ngram/1", ""}:
            raise ValueError("a model backend is MODULE:ATTR; the default backend is 'hash'")
        self.model = load(spec)
        path = getattr(self.model, "weights_path", None)
        if not isinstance(path, (str, Path)) or not Path(path).is_file():
            raise ValueError(f"{spec} names no local weights_path file; weights are never fetched")
        self.weights_digest = "sha256:" + _file_sha256(Path(path))
        if weights_pin and weights_pin != self.weights_digest:
            raise ValueError(
                f"weights digest {self.weights_digest} does not match the pin {weights_pin}"
            )
        self.spec, self.name, self.dim = spec, str(self.model.name), int(self.model.dim)

    def description(self) -> dict[str, Any]:
        return {"name": self.name, "dim": self.dim, "adapter": self.spec,
                "weights_digest": self.weights_digest, "norm": "l2"}  # fmt: skip

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for vector in self.model.embed(texts):
            if len(vector) != self.dim or not all(math.isfinite(float(v)) for v in vector):
                raise ValueError(
                    f"{self.spec} returned a vector that is not {self.dim} finite numbers"
                )
            norm = math.sqrt(sum(float(v) * float(v) for v in vector))
            out.append([float(v) / norm for v in vector] if norm else [float(v) for v in vector])
        return out


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load(spec: str | None = None, weights_pin: str | None = None) -> Any:
    """``hash`` (or None) -> :class:`HashBackend`; ``MODULE:ATTR`` -> :class:`ModelBackend`."""
    if spec in (None, "", "hash", NAME):
        if weights_pin:
            raise ValueError("--weights-digest applies to a model backend only")
        return HashBackend()
    return ModelBackend(spec, weights_pin)


def backend_digest(backend: Any) -> str:
    return digest_of(backend.description())


__all__ = ["DIM", "NAME", "HashBackend", "ModelBackend", "backend_digest", "digest_of", "load"]
