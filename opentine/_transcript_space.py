"""Transcript embeddings for corpus-scale analysis (0.74).

The default backend, ``opentine.tfidf-hash/1``, is standard library only and
deterministic: no model and no network. A transcript's features are its
case-folded ``\\w+`` words and word bigrams; each feature is hashed with a
seeded CRC-32 into one of ``dim`` buckets with a sign taken from another bit
(a sparse random projection). A feature weighs ``(1 + ln tf) * idf`` with
``idf = ln((N + 1) / (df + 1)) + 1`` over the corpus being analysed, and each
vector is L2-normalised. Similarity search subtracts the corpus mean vector
first (centred cosine), so what every transcript shares does not rank.

:func:`backend_digest` is the SHA-256 of the canonical JSON of the backend's
parameters; every result records it. :func:`Space.corpus_digest` names the
corpus the IDF was fitted on (sorted ``id`` and text digest pairs).

A pinned local model can stand in through ``MODULE:ATTR`` (the protocol of
:mod:`opentine.repository._embed`) when the object also carries
``weights_digest`` (``sha256:<hex>``): the digest is recorded with the backend
and a model without one is refused. Nothing is downloaded; such adapters must
load weights from local files only (docs/TRANSCRIPT_FLAGS.md).
"""

from __future__ import annotations

import hashlib
import math
import re
import zlib
from collections import Counter
from typing import Any

from opentine.kernel import canonical_json

NAME = "opentine.tfidf-hash/1"
DIM = 2048
SEED = 74
HASH_MASK = (1 << 21) - 1  # keeps bucket (h % dim, dim | 2**21) and sign (bit 20)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
Sparse = dict[int, float]


def params(dim: int = DIM, seed: int = SEED) -> dict[str, Any]:
    return {"name": NAME, "dim": dim, "seed": seed, "features": "word+word-bigram",
            "normalise": "nfkc+casefold+drop-Cf+confusables/1+base64-decode", "mask": 21,
            "hash": "crc32(feature, seed); bucket=h%dim; sign=bit20",
            "weight": "(1+ln tf)*(ln((N+1)/(df+1))+1)", "similarity": "centred cosine"}  # fmt: skip


def digest_of(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def backend_digest(dim: int = DIM, seed: int = SEED) -> str:
    return digest_of(params(dim, seed))


def features(text: str, seed: int = SEED) -> Counter[int]:
    """Hashed word and bigram counts over every normalised word (streamed, no cap)."""
    from opentine._transcript_normalise import words

    out: Counter[int] = Counter()
    previous = None
    for word in words(text):
        out[zlib.crc32(word.encode("utf-8"), seed) & HASH_MASK] += 1
        if previous is not None:
            out[zlib.crc32(f"{previous} {word}".encode(), seed) & HASH_MASK] += 1
        previous = word
    return out


def _normalise(vector: Sparse) -> Sparse:
    norm = math.sqrt(sum(v * v for v in vector.values()))
    return {k: v / norm for k, v in vector.items()} if norm else vector


def dot(a: Sparse, b: Sparse | list[float]) -> float:
    if isinstance(b, list):
        return sum(v * b[k] for k, v in a.items())
    if len(b) < len(a):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())


class Space:
    """A fitted space: IDF and mean over one corpus; sparse vectors and centred scores."""

    def __init__(self, texts: dict[str, str], *, dim: int = DIM, seed: int = SEED,
                 model: Any = None) -> None:  # fmt: skip
        self.dim, self.seed, self.model = dim, seed, model
        self.ids = sorted(texts)
        digests = {i: digest_of(texts[i]) for i in self.ids}
        self.corpus_digest = digest_of([[i, digests[i]] for i in self.ids])
        # content order: run ids hash a wall-clock time, so seeding by id order
        # would make the same transcripts cluster differently on each recording
        self.order = sorted(self.ids, key=lambda i: (digests[i], i))
        if model is not None:
            dense = model.embed([texts[i] for i in self.ids]) if self.ids else []
            self.dim = int(model.dim)
            self.vectors = {i: self._dense(v) for i, v in zip(self.ids, dense, strict=True)}
        else:
            counts = {i: features(texts[i], seed) for i in self.ids}
            df: Counter[int] = Counter()
            for c in counts.values():
                df.update(c.keys())
            n = len(self.ids)
            self.idf = {h: math.log((n + 1) / (d + 1)) + 1 for h, d in df.items()}
            self.vectors = {i: self._weigh(c) for i, c in counts.items()}
        mean = [0.0] * self.dim
        for vector in self.vectors.values():
            for k, v in vector.items():
                mean[k] += v
        self.mean = [m / max(1, len(self.ids)) for m in mean]
        self._mm = sum(m * m for m in self.mean)
        self._norm = {i: self._centred_norm(v) for i, v in self.vectors.items()}

    def _dense(self, values: Any) -> Sparse:
        """A model's vector, refused unless it has ``dim`` finite numbers."""
        vector = [float(v) for v in values]
        if len(vector) != self.dim:
            raise ValueError(f"the model returned dimension {len(vector)}, not {self.dim}")
        if not all(math.isfinite(v) for v in vector):
            raise ValueError("the model returned a vector that is not all finite numbers")
        return _normalise(dict(enumerate(vector)))

    def _weigh(self, counts: Counter[int]) -> Sparse:
        vector: Sparse = {}
        for h, tf in counts.items():
            weight = (1 + math.log(tf)) * self.idf.get(h, 1.0)
            bucket = h % self.dim
            vector[bucket] = vector.get(bucket, 0.0) + (weight if (h >> 20) & 1 else -weight)
        return _normalise(vector)

    def _centred_norm(self, vector: Sparse) -> float:
        return math.sqrt(max(1e-12, 1.0 - 2 * dot(vector, self.mean) + self._mm))

    def embed(self, text: str) -> Sparse:
        """A vector for *text* in this space (IDF from the fitted corpus)."""
        if self.model is not None:
            return self._dense(self.model.embed([text])[0])
        return self._weigh(features(text, self.seed))

    def query(self, vectors: list[Sparse]) -> list[float]:
        """The centroid of the centred, normalised *vectors* (a dense query)."""
        out = [0.0] * self.dim
        for vector in vectors:
            n = self._centred_norm(vector)
            for k in range(self.dim):
                out[k] -= self.mean[k] / n
            for k, v in vector.items():
                out[k] += v / n
        return out

    def score(self, query: list[float], run: str) -> float:
        """Centred cosine-like score of *run* against a :meth:`query` vector."""
        qm = sum(q * m for q, m in zip(query, self.mean, strict=True))
        return (dot(self.vectors[run], query) - qm) / self._norm[run]

    def backend(self) -> dict[str, Any]:
        if self.model is not None:
            return {"name": str(self.model.name), "dim": self.dim,
                    "digest": digest_of({"name": str(self.model.name), "dim": self.dim,
                                         "weights_digest": self.model.weights_digest}),
                    "weights_digest": self.model.weights_digest}  # fmt: skip
        return {"name": NAME, "dim": self.dim, "digest": backend_digest(self.dim, self.seed),
                "weights_digest": None}  # fmt: skip


def load_model(spec: str | None) -> Any:
    """``None`` for the default backend, else a pinned local model (``MODULE:ATTR``)."""
    if spec in (None, "", NAME, "tfidf-hash"):
        return None
    from opentine.repository._embed import load

    model = load(spec)
    pinned = getattr(model, "weights_digest", None)
    if not isinstance(pinned, str) or not _DIGEST.fullmatch(pinned):
        raise ValueError(f"{spec} has no weights_digest (sha256:<hex>): a model backend is pinned")
    return model


__all__ = ["DIM", "NAME", "SEED", "Space", "backend_digest", "digest_of", "dot", "features",
           "load_model", "params"]  # fmt: skip
