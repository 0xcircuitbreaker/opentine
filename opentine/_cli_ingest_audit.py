"""``tine ingest seal|audit|prove|segments`` (0.84): RL-scale capture audits.

* ``seal``: Merkle-root the batches since the stream's previous segment into
  one signed segment (``opentine.ingest-segment/1``, :mod:`opentine._rl_segment`);
* ``audit``: a commit-then-reveal sampling audit of a segment for a stated
  guarantee (``opentine.ingest-audit/1``, :mod:`opentine._rl_audit`);
* ``prove``: an RFC 9162 inclusion proof of one episode in a segment;
* ``segments``: check every segment and audit of a stream
  (:mod:`opentine._rl_verify`), exit 1 on a ``fail:`` finding.

``--json`` follows ``tine-cli-ingest-1`` (docs/RL-CAPTURE.md).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

VERBS = ("seal", "audit", "prove", "segments")


def add_verbs(verbs: argparse._SubParsersAction) -> list[argparse.ArgumentParser]:
    seal = verbs.add_parser("seal", help="Seal the batches since the last segment (Merkle root)")
    seal.add_argument("--stream", required=True, metavar="NAME", help="The ingest stream")
    seal.add_argument("--key", required=True, metavar="KEY", help="A pinned runner-role key")
    seal.add_argument("--through", metavar="BATCH", help="Last batch to seal (default: newest)")
    audit = verbs.add_parser("audit", help="Sampling audit of a sealed segment")
    audit.add_argument("segment", metavar="SEGMENT", help="Segment attestation id")
    audit.add_argument("--key", required=True, metavar="KEY", help="A pinned auditor-role key")
    audit.add_argument("--confidence", default="0.99", help="Detection confidence, in (0, 1)")
    audit.add_argument("--max-bad", default="0.005",
                       help="Tolerated share of bad episodes, in [0, 1)")  # fmt: skip
    audit.add_argument("--checkpoint", metavar="FILE",
                       help="Signed op log checkpoint (default: the log's own)")  # fmt: skip
    audit.add_argument("--episodes", metavar="FILE",
                       help="Stored episode lines to audit (default: the batches)")  # fmt: skip
    prove = verbs.add_parser("prove", help="Inclusion proof of one episode in a segment")
    prove.add_argument("segment", metavar="SEGMENT", help="Segment attestation id")
    prove.add_argument("--index", required=True, type=int, help="The episode's stream index")
    segments = verbs.add_parser("segments", help="Check a stream's segments and audits")
    segments.add_argument("stream", metavar="STREAM", help="The ingest stream")
    segments.add_argument("--strict", action="store_true", help="Advisory findings block too")
    return [seal, audit, prove, segments]


def _seal(args: argparse.Namespace, repo: Any, at_ms: int) -> tuple[dict, list[str], int]:
    from opentine._key_hygiene import ed25519_private
    from opentine._rl_segment import seal

    row = seal(repo, args.stream, ed25519_private(args.key), at_ms=at_ms, through=args.through)
    line = (f"segment {row['seq']} of {row['stream']}: {row['episodes']} episodes in "
            f"{len(row['batches'])} batches, root {row['root']} ({row['id']})")  # fmt: skip
    return {"segment": row}, [line], 0


def _audit(args: argparse.Namespace, repo: Any, at_ms: int) -> tuple[dict, list[str], int]:
    from opentine._key_hygiene import ed25519_private
    from opentine._rl_audit import run

    checkpoint = Path(args.checkpoint).read_bytes() if args.checkpoint else None
    source = Path(args.episodes).read_bytes() if args.episodes else None
    row = run(repo, args.segment, ed25519_private(args.key), confidence=args.confidence,
              max_bad=args.max_bad, at_ms=at_ms, checkpoint=checkpoint, source=source)  # fmt: skip
    lines = [f"{f['status']}: episode {f['index']} (position {f['position']})"
             for f in row["failures"]]  # fmt: skip
    lines.append(f"audit {row['id']}: {row['checked']} of {row['episodes']} sampled "
                 f"({row['guarantee']['confidence']} confidence, at most "
                 f"{row['guarantee']['max_bad']} bad), {row['missing']} missing, "
                 f"{row['altered']} altered: {row['verdict'].upper()}")  # fmt: skip
    return {"audit": row}, lines, 0 if row["verdict"] == "pass" else 1


def _prove(args: argparse.Namespace, repo: Any, at_ms: int) -> tuple[dict, list[str], int]:
    from opentine._rl_audit import prove

    doc = prove(repo, args.segment, args.index)
    return (
        {"proof": doc},
        [
            f"episode {doc['index']} at position {doc['position']} of "
            f"{doc['size']}: {len(doc['proof'])} hashes to {doc['root']}"
        ],
        0,
    )


def _segments(args: argparse.Namespace, repo: Any, at_ms: int) -> tuple[dict, list[str], int]:
    from opentine._rl_verify import verify

    report = verify(repo, args.stream)
    blocking = [f for f in report["findings"] if args.strict or f["level"] == "fail"]
    lines = [f"{f['level']}: {f['code']} {f['record'] or ''} {f['message']}".replace("  ", " ")
             for f in report["findings"]]  # fmt: skip
    lines.append(f"{report['stream']}: {len(report['segments'])} segments, "
                 f"{report['episodes']} episodes: {'FAILED' if blocking else 'ok'}")  # fmt: skip
    return {"report": report}, lines, 1 if blocking else 0


HANDLERS = {"seal": _seal, "audit": _audit, "prove": _prove, "segments": _segments}

__all__ = ["HANDLERS", "VERBS", "add_verbs"]
