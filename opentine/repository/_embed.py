"""Local text embedders for hybrid search (0.46, ``opentine[embed]``).

An embedder turns text into a fixed-length vector. It is pluggable and local:

* ``hash`` (the default, ``hash-ngram/1``) is :class:`HashEmbedder`: character
  trigram and word features hashed into 256 signed buckets, L2-normalised.
  Standard library only and deterministic, so an index built on one machine
  ranks the same on another. It captures spelling overlap, not meaning.
* ``MODULE:ATTR`` names a Python object importable on this machine with a
  ``name``, a ``dim`` and ``embed(texts) -> list[list[float]]`` -- for example
  an adapter around a local sentence-transformers or ONNX model (docs/SEARCH.md).
  A spec that looks like a URL is refused: text is never sent anywhere to be
  embedded.

``OPENTINE_EMBEDDER`` supplies the spec when ``--embedder`` is not given. The
``embed`` extra installs numpy, which the index uses for the similarity scan
when present; without it the scan is pure Python with the same results.
"""

from __future__ import annotations

import hashlib
import importlib
import math
import os
import re
from typing import Protocol, runtime_checkable

ENV = "OPENTINE_EMBEDDER"
_SPEC = re.compile(r"[A-Za-z_][\w.]*:[A-Za-z_]\w*")
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,64}")
_WORD = re.compile(r"\w+", re.UNICODE)
MAX_EMBED_DIM = 8192


@runtime_checkable
class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def normalise(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    return [value / norm for value in vector] if norm else list(vector)


class HashEmbedder:
    """``hash-ngram/1``: hashed word and character-trigram features, signed, L2-normalised."""

    name = "hash-ngram/1"
    dim = 256

    def _one(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        for word in _WORD.findall(text.casefold())[:20000]:
            padded = f" {word} "
            grams = [word] + [padded[i : i + 3] for i in range(len(padded) - 2)]
            for gram in grams:
                digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=4).digest()
                bucket = int.from_bytes(digest[:3], "little") % self.dim
                vector[bucket] += 1.0 if digest[3] & 1 else -1.0
        return normalise(vector)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(text) for text in texts]


def load(spec: str | None = None) -> Embedder:
    """The embedder a spec names (``hash`` or ``MODULE:ATTR``)."""
    spec = (spec if spec is not None else os.environ.get(ENV, "hash")).strip()
    if spec in {"", "hash", "hash-ngram/1"}:
        return HashEmbedder()
    if "://" in spec or not _SPEC.fullmatch(spec):
        raise ValueError(
            f"embedder {spec!r} is not hash or MODULE:ATTR; embeddings are computed locally only"
        )
    module, _, attr = spec.partition(":")
    found = getattr(importlib.import_module(module), attr)
    found = found() if isinstance(found, type) else found
    if not isinstance(found, Embedder) or not _NAME.fullmatch(str(found.name)):
        raise ValueError(f"{spec} has no usable name, dim and embed(texts)")
    if type(found.dim) is not int or not 1 <= found.dim <= MAX_EMBED_DIM:
        raise ValueError(f"{spec} has a dim outside 1..{MAX_EMBED_DIM}")
    return found


__all__ = ["ENV", "Embedder", "HashEmbedder", "load", "normalise"]
