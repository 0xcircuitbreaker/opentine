"""``tine dataset contamination`` (0.61): holdout items found in a training corpus.

Two checks, both recorded in the result so a reader can redo them:

* **exact**: each item's text as a ``blob`` object id (``blob:sha256:...``,
  schema 1, UTF-8 bytes). A holdout item whose oid is in the corpus, or stored
  in the repository given with ``--repo``, leaked verbatim.
* **near-duplicate**: word 5-gram shingles (lower-cased ``\\w+`` tokens),
  MinHash signatures (128 permutations, ``(a*x + b) mod 2^61-1`` over a 64-bit
  BLAKE2b of the shingle, coefficients from SHA-256 of the permutation
  index), banded LSH (32 bands of 4 rows) to find candidates, then the *exact*
  Jaccard of the two shingle sets. A pair at or above the threshold (default
  0.8) is reported with both the exact and the estimated Jaccard. LSH keeps the
  work proportional to candidates, not to holdout x corpus pairs.
* **chunked**: an item split across several corpus items (each under the
  threshold alone) is caught by coverage, the share of its shingles found in
  the union of corpus shingles, at or above the same threshold.

Text is folded first (NFKC, case folding, Cyrillic/Greek lookalikes, format
characters dropped; :mod:`opentine._canary_norm`) so those mutations do not
lower the overlap.

Embedding similarity is out of scope here. Item text is ``input`` (a string as
is, anything else as canonical JSON), then ``expected`` when present.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

NGRAM = 5
PERMS = 128
BANDS = 32
ROWS = PERMS // BANDS
THRESHOLD = 0.8
_P = (1 << 61) - 1
_WORD = re.compile(r"\w+")


def _coeffs() -> list[tuple[int, int]]:
    out = []
    for i in range(PERMS):
        seed = hashlib.sha256(f"opentine.minhash/{i}".encode()).digest()
        out.append((int.from_bytes(seed[:8], "big") % (_P - 1) + 1,
                    int.from_bytes(seed[8:16], "big") % _P))  # fmt: skip
    return out


_COEFFS = _coeffs()


def item_text(item: dict[str, Any]) -> str:
    from opentine.kernel import canonical_json

    parts = []
    for name in ("input", "expected"):
        value = item.get(name)
        if value is not None:
            parts.append(value if isinstance(value, str) else canonical_json(value).decode())
    return "\n".join(parts)


def oid(text: str) -> str:
    from opentine.kernel import object_id

    return object_id("blob", 1, text.encode("utf-8"))


def shingles(text: str) -> frozenset[str]:
    from opentine._canary_norm import fold_words

    words = _WORD.findall(fold_words(text))
    if len(words) < NGRAM:
        return frozenset([" ".join(words)]) if words else frozenset()
    return frozenset(" ".join(words[i : i + NGRAM]) for i in range(len(words) - NGRAM + 1))


def signature(grams: frozenset[str]) -> tuple[int, ...]:
    if not grams:
        return ()
    xs = [int.from_bytes(hashlib.blake2b(g.encode("utf-8"), digest_size=8).digest(), "big")
          for g in grams]  # fmt: skip
    return tuple(min((a * x + b) % _P for x in xs) for a, b in _COEFFS)


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    return len(a & b) / len(a | b) if a or b else 0.0


def _bands(sig: tuple[int, ...]) -> list[tuple[int, tuple[int, ...]]]:
    return [(i, sig[i * ROWS : (i + 1) * ROWS]) for i in range(BANDS)] if sig else []


def check(holdout: list[dict[str, Any]], corpus: list[tuple[str, dict[str, Any]]], *,
          threshold: float = THRESHOLD, repo: Any = None) -> dict[str, Any]:  # fmt: skip
    """``{ok, method, counts, exact, near}`` for holdout items against ``(where, item)`` rows."""
    if not 0.0 < threshold <= 1.0:
        raise ValueError("threshold is in (0, 1]")
    by_oid: dict[str, list[str]] = defaultdict(list)
    owners: dict[str, list[str]] = defaultdict(list)
    buckets: dict[tuple[int, tuple[int, ...]], list[int]] = defaultdict(list)
    prepared = []
    for index, (where, item) in enumerate(corpus):
        text = item_text(item)
        by_oid[oid(text)].append(where)
        grams = shingles(text)
        sig = signature(grams)
        prepared.append((where, grams, sig))
        for gram in grams:
            if len(owners[gram]) < 8:
                owners[gram].append(where)
        for band in _bands(sig):
            buckets[band].append(index)
    exact, near, chunked, compared = [], [], [], 0
    for item in holdout:
        text = item_text(item)
        item_oid = oid(text)
        places = list(by_oid.get(item_oid, []))
        if repo is not None and repo.has(item_oid):
            places.append("repo")
        if places:
            exact.append({"id": str(item.get("id")), "oid": item_oid, "found_in": places})
            continue
        grams = shingles(text)
        sig = signature(grams)
        candidates = sorted({i for band in _bands(sig) for i in buckets.get(band, [])})
        compared += len(candidates)
        hit = False
        for i in candidates:
            where, other, other_sig = prepared[i]
            score = jaccard(grams, other)
            if score >= threshold:
                est = sum(x == y for x, y in zip(sig, other_sig, strict=True)) / PERMS
                near.append({"id": str(item.get("id")), "found_in": where,
                             "jaccard": round(score, 6), "minhash_estimate": est})  # fmt: skip
                hit = True
        shared = [g for g in grams if g in owners]
        if not hit and len(grams) > 1 and len(shared) / len(grams) >= threshold:
            sources = sorted({w for g in shared for w in owners[g]})
            chunked.append({"id": str(item.get("id")), "found_in": sources,
                            "coverage": round(len(shared) / len(grams), 6)})  # fmt: skip
    method = {"exact": "blob oid of UTF-8 item text", "shingle": f"word {NGRAM}-gram",
              "permutations": PERMS, "bands": BANDS, "rows": ROWS,
              "threshold": threshold, "coverage": "item shingles in corpus union"}  # fmt: skip
    counts = {"holdout": len(holdout), "corpus": len(corpus), "candidates": compared,
              "exact": len(exact), "near": len(near), "chunked": len(chunked)}  # fmt: skip
    return {"ok": not (exact or near or chunked), "method": method, "counts": counts,
            "exact": exact, "near": near, "chunked": chunked}  # fmt: skip


def corpus_rows(paths: list[str]) -> list[tuple[str, dict[str, Any]]]:
    from opentine._eval_dataset import read_jsonl

    rows = []
    for path in paths:
        for item in read_jsonl(Path(path)):
            rows.append((f"{Path(path).as_posix()}#{item.get('id')}", item))
    return rows


__all__ = ["THRESHOLD", "check", "corpus_rows", "item_text", "jaccard", "oid", "shingles",
           "signature"]  # fmt: skip
