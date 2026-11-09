"""``tine serve`` flags for X15 admission: quota (429) and VSA emission."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine.remote._quota import QuotaAdmission
from opentine.remote._vsa import TrustPolicyAdmission, admitted_levels, directory_sink


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
    group.add_argument(
        "--vsa-signing-key",
        metavar="FILE",
        help="Sign each VSA (DSSE, Ed25519) with the server's own key: a 32-byte seed or "
        "64-char hex; its public half is advertised in capabilities.vsa.keys",
    )
    group.add_argument(
        "--trust-policy",
        dest="admission_policy",
        action="append",
        default=[],
        metavar="NAME=FILE",
        help="Admit ref updates only under this named opentine.admission-policy (repeatable, "
        "first match decides); each VSA records the deciding policy",
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
    specs = getattr(args, "admission_policy", None) or []
    signing = getattr(args, "vsa_signing_key", None)
    if getattr(args, "vsa_dir", None) or specs or signing:
        check: Any = admitted_levels
        if specs:
            from opentine.remote._admission_policy import PolicyCheck, load_policies

            try:
                check = PolicyCheck(load_policies(specs))
            except (OSError, ValueError) as exc:
                raise SystemExit(f"tine serve: {exc}") from exc
        sink = directory_sink(args.vsa_dir) if getattr(args, "vsa_dir", None) else None
        key = None
        if signing:
            from opentine._signing_keys import SignatureError, load_ed25519_private

            try:
                key = load_ed25519_private(Path(signing).read_bytes())
            except (OSError, SignatureError) as exc:
                raise SystemExit(f"tine serve: --vsa-signing-key: {exc}") from exc
        policy = TrustPolicyAdmission(check, sink=sink, inner=policy, private_key=key)
    return policy
