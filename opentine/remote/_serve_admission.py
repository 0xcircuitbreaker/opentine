"""``tine serve`` flags for X15 admission: quota (429) and VSA emission."""

from __future__ import annotations

import argparse
from typing import Any

from opentine.remote._quota import QuotaAdmission
from opentine.remote._vsa import TrustPolicyAdmission, directory_sink


def add_admission_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("admission (X15)")
    group.add_argument(
        "--quota-rate",
        type=float,
        metavar="PER_SECOND",
        help="Per-tenant/subject token refill rate; over-quota requests get 429",
    )
    group.add_argument("--quota-burst", type=float, default=60.0, help="Token bucket size (60)")
    group.add_argument(
        "--quota-max-keys", type=int, default=10_000, help="Buckets tracked before LRU eviction"
    )
    group.add_argument(
        "--vsa-dir", metavar="DIR", help="Write a SLSA VSA for every admitted push to DIR"
    )


def serve_admission(args: argparse.Namespace) -> Any:
    """The admission chain the flags ask for, or None for the default allow-all."""
    policy: Any = None
    if getattr(args, "quota_rate", None) is not None:
        try:
            policy = QuotaAdmission(
                rate=args.quota_rate, burst=args.quota_burst, max_keys=args.quota_max_keys
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    if getattr(args, "vsa_dir", None):
        policy = TrustPolicyAdmission(sink=directory_sink(args.vsa_dir), inner=policy)
    return policy
