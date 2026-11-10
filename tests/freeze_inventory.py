"""The 0.48 freeze-cutoff inventory: every object kind and wire format, and its vectors.

``tests/test_048_freeze_cutoff.py`` enumerates kinds from the tree (SPEC
headings, ``docs/schemas``, ``docs/conformance/vectors``) and checks each is
here, and that each entry's families are answered by Python, the TS verifier
and ``tine-verify.pyz``. Since 0.50 (ROADMAP criterion 2) every entry's pyz
evidence is ``CONFORM``: the built pyz's ``_pyz/_conform`` answers every reader
and verifier case of the family, case by case, and ``PYZ_OP_GAPS``,
``PYZ_FILE_LEVEL`` and ``DEFERRED`` are empty. ``scripts/check_parity.py``
compares Python, the TS verifier and the pyz on every one of those cases.

``STORAGE`` families are repository internals the pyz never opens (it reads
exported files, not repositories: refs, reflogs, shallow files, packs, the
repository config); ``WRITER`` families are writer-side only. Both may only
shrink.
"""

from __future__ import annotations

CONFORM = "conform"


#: entry -> (SPEC section, names it covers, schema stems, families, pyz evidence)
KINDS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], object]] = {
    "canonical JSON": ("0.2", (), (), ("01-selftest", "02-canon-v3", "03-canon-v2",
                                       "04-divergence", "09-canon-v4"), CONFORM),
    "text and shape": ("0.1", (), (), ("00-text", "05-shape"), CONFORM),
    "stored objects": ("1.5.6", (), (), ("15-links", "15b-metrics", "15c-graph", "15d-load"),
                       CONFORM),
    "v3 objects": ("1.5", ("blob", "event", "run", "attestation", "annotation"), (),
                   ("12-envelope", "13-oid"), CONFORM),
    ".tine artifact": ("3", (".tine",), ("tine-run-1", "tine-step-1"),
                       ("31-artifact-v2", "35-integrity", "51-compat", "54-artifact-v5"), CONFORM),
    "signatures": ("4", ("tine-sig/1", "tine-sig/2", "tine-sig/3", "tine-attest/1",
                         "tine-attest/2"), ("tine-sig-3",),
                   ("42-signing", "47-verdict", "53-sig-v4", "55-sig-pq"), CONFORM),
    "actions": ("4.8", ("tine-actions/1",), (), ("48-actions",), CONFORM),
    "agent": ("4.9", ("opentine-agent/1",), (), ("49-agent",), CONFORM),
    "delegation": ("4.10", ("opentine-delegation/1",), ("opentine-delegation-1",),
                   ("56-delegation", "76-delegation-revocation"), CONFORM),
    "fleet": ("4.11", ("opentine-fleet/1",), ("opentine-fleet-1",), ("78-fleet",), CONFORM),
    "eval verdict": ("4.12", ("tine-eval-verdict/1",), ("tine-eval-verdict-1",),
                     ("58-eval-verdict",), CONFORM),
    "redaction report": ("4.13", ("opentine.redaction-report",),
                         ("opentine-redaction-report-1",), ("60-redaction-report",), CONFORM),
    "redaction report v2": ("4.13.1", ("opentine-redaction/3",),
                            ("opentine-redaction-report-2",), ("62-redaction-report-v2",), CONFORM),
    "tombstone": ("4.14", ("opentine.tombstone",), ("opentine-tombstone-1",),
                  ("63-tombstone",), CONFORM),
    "redacted copy": ("4.15", ("opentine.redacted-copy",), ("opentine-redacted-copy-1",),
                      ("64-redacted-copy",), CONFORM),
    "project": ("4.16", ("opentine.project", "opentine.mirror-state"),
                ("opentine-project-1", "opentine-mirror-state-1"),
                ("65-project", "66-mirror-state"), CONFORM),
    "merge": ("4.19", ("opentine.merge",), ("opentine-merge-1", "opentine-merge-approval-1"),
              ("68-merge",), CONFORM),
    "review": ("4.20", ("opentine.review", "opentine.review-gate"),
               ("opentine-review-1", "opentine-review-gate-1", "opentine-review-bundle-1"),
               ("70-review",), CONFORM),
    "prompt": ("4.21", ("opentine.prompt",), ("opentine-prompt-1",), ("71-prompt",), CONFORM),
    "memory": ("4.22", ("opentine.memory",), ("opentine-memory-1",), ("69-memory",), CONFORM),
    "forge claim": ("4.23", ("opentine.forge-claim",), ("opentine-forge-claim-1",),
                    ("72-forge-claim",), CONFORM),
    "forge check": ("4.24", ("opentine.forge-check",), ("opentine-forge-check-1",),
                    ("73-forge-check",), CONFORM),
    "review finding": ("4.25", ("opentine.review-finding",), ("opentine-review-finding-1",),
                       ("74-review-finding",), CONFORM),
    "OMS model signature": ("4.26", (), (), ("75-oms",), CONFORM),
    "transparency log": ("8.10", ("opentine-log/1",),
                         ("opentine-tlog-checkpoint-1", "opentine-tlog-receipt-1"),
                         ("57-tlog",), CONFORM),
    "webhook": ("8.13", ("tine-webhook/1",), ("tine-webhook-1", "tine-event-1"),
                ("59-webhook",), CONFORM),
    "hook": ("8.16", ("opentine-hook/1",), ("opentine-hook-1",), ("67-hook",), CONFORM),
    "admission VSA": ("8.17", (), ("opentine-admission-policy-1",), ("61-vsa",), CONFORM),
    "keyless signing time": ("8.12.1", (), (), ("77-keyless-tsa",), CONFORM),
    # 0.50: the six pre-cutoff kinds the 0.48 audit left without vectors.
    "verify report": ("8.7", ("tine-verify-report/2",), ("tine-verify-report-2",),
                      ("79-verify-report",), CONFORM),
    "custody": ("8.4", ("tine-custody/1", "opentine-custody/1"), (), ("80-custody",), CONFORM),
    "replay predicate": ("8.8", ("replay/v1",), (), ("81-replay",), CONFORM),
    "sealed objects": ("11", ("TINEAES6",), (), ("82-sealed6",), CONFORM),
    "line attribution": ("8.24", ("opentine-line-attribution/1",),
                         ("opentine-line-attribution-1",), ("83-line-attribution",), CONFORM),
    "cost statement": ("8.25", ("tine-cost-statement/1",), ("tine-cost-statement-1",),
                       ("84-cost-statement",), CONFORM),
}  # fmt: skip

#: Repository internals: the pyz verifies exported files and never opens a repository.
STORAGE = (
    "16-bounds", "22-layout", "24-refs", "26-reflog", "27-shallow", "28-pack", "29-localpack",
    "99-repair",
)  # fmt: skip
WRITER = ("14-redaction",)

#: Kinds in the tree with no conformance family. Emptied in 0.50 (families 79-84);
#: it may only stay empty.
DEFERRED: dict[str, str] = {}

#: Schemas that describe no stored or exchanged kind (CLI outputs, local config, imports).
NOT_KINDS = (
    "agent-trace-0.1", "opentine-merge-gates-1", "opentine-plugin-allow-1", "tine-ai-share-1",
    "tine-assurance-1", "tine-blame-1", "tine-ci-gate-1", "tine-experts-1", "tine-help-1",
    "tine-list-page-1", "tine-redaction-rules-1", "tine-repo-show-1", "tine-search-results-1",
    "tine-share-1", "tine-verify-dataset-1", "tine-watch-1", "tine-graph-1",
    "opentine-compliance-profile-1",
    "opentine-witness-network-1",  # 0.49: a pinned config, like --witness-vkey flags
)  # fmt: skip
DEFERRED_SCHEMAS: dict[str, str] = {}
#: Backticked SPEC heading words that are not kinds (capabilities, commands, fields).
NOT_KIND_NAMES = (
    "caps.project", "caps.social_export", "caps.reviews", "caps.coord", "recall",
    "tine witness serve", "tine-experts/1", "/1", "upgraded_from",
)  # fmt: skip

#: CONFORM families the pyz checks only as whole files, not case by case. Emptied
#: in 0.50 (Python/TS/pyz parity, ROADMAP criterion 2); it may only stay empty.
PYZ_FILE_LEVEL: dict[str, str] = {}

#: Reader/verifier ops in CONFORM families the pyz does not answer op-for-op.
#: Emptied in 0.50; it may only stay empty.
PYZ_OP_GAPS: dict[str, str] = {}
