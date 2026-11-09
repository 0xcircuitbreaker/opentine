"""The 0.48 freeze-cutoff inventory: every object kind and wire format, and its vectors.

``tests/test_048_freeze_cutoff.py`` enumerates kinds from the tree (SPEC
headings, ``docs/schemas``, ``docs/conformance/vectors``) and checks each is
here, and that each entry's families are answered by Python, the TS verifier
and ``tine-verify.pyz``. How the pyz answers is the entry's ``pyz``:

* ``CONFORM`` -- the built pyz's ``_pyz/_conform`` runs the family's cases;
  ops it does not answer are pinned in ``PYZ_OP_GAPS``.
* ``("test", path)`` -- an existing test runs the family through the pyz.

``STORAGE`` families are repository internals the pyz never opens (it reads
exported files, not repositories); ``WRITER`` families are writer-side only;
``DEFERRED`` are kinds that predate the cutoff and have no vectors yet. 0.49
may add tests for those (it adds no kind); this list may only shrink.
"""

from __future__ import annotations

CONFORM = "conform"


def T(path: str) -> tuple[str, str]:
    return ("test", path)


#: entry -> (SPEC section, names it covers, schema stems, families, pyz evidence)
KINDS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], object]] = {
    "canonical JSON": ("0.2", (), (), ("01-selftest", "02-canon-v3", "03-canon-v2",
                                       "04-divergence", "09-canon-v4"), CONFORM),
    "text and shape": ("0.1", (), (), ("00-text", "05-shape"), CONFORM),
    "v3 objects": ("1.5", ("blob", "event", "run", "attestation", "annotation"), (),
                   ("12-envelope", "13-oid"), CONFORM),
    ".tine artifact": ("3", (".tine",), ("tine-run-1", "tine-step-1"),
                       ("31-artifact-v2", "35-integrity", "51-compat", "54-artifact-v5"),
                       CONFORM),
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
                         ("opentine-redaction-report-1",), ("60-redaction-report",),
                         T("tests/test_0451_redaction_followups.py")),
    "redaction report v2": ("4.13.1", ("opentine-redaction/3",),
                            ("opentine-redaction-report-2",), ("62-redaction-report-v2",),
                            T("tests/test_046_pii.py")),
    "tombstone": ("4.14", ("opentine.tombstone",), ("opentine-tombstone-1",),
                  ("63-tombstone",), T("tests/test_046_redacted_public.py")),
    "redacted copy": ("4.15", ("opentine.redacted-copy",), ("opentine-redacted-copy-1",),
                      ("64-redacted-copy",), T("tests/test_046_redacted_public.py")),
    "project": ("4.16", ("opentine.project", "opentine.mirror-state"),
                ("opentine-project-1", "opentine-mirror-state-1"),
                ("65-project", "66-mirror-state"), T("tests/test_0461_projects.py")),
    "merge": ("4.19", ("opentine.merge",), ("opentine-merge-1", "opentine-merge-approval-1"),
              ("68-merge",), T("tests/test_047_merge.py")),
    "review": ("4.20", ("opentine.review", "opentine.review-gate"),
               ("opentine-review-1", "opentine-review-gate-1", "opentine-review-bundle-1"),
               ("70-review",), T("tests/test_047_reviews.py")),
    "prompt": ("4.21", ("opentine.prompt",), ("opentine-prompt-1",), ("71-prompt",),
               T("tests/test_047_registry.py")),
    "memory": ("4.22", ("opentine.memory",), ("opentine-memory-1",), ("69-memory",),
               T("tests/test_047_registry.py")),
    "forge claim": ("4.23", ("opentine.forge-claim",), ("opentine-forge-claim-1",),
                    ("72-forge-claim",), CONFORM),
    "transparency log": ("8.10", ("opentine-log/1",),
                         ("opentine-tlog-checkpoint-1", "opentine-tlog-receipt-1"),
                         ("57-tlog",), CONFORM),
    "webhook": ("8.13", ("tine-webhook/1",), ("tine-webhook-1", "tine-event-1"),
                ("59-webhook",), T("tests/test_0451_watch_verifiers.py")),
    "hook": ("8.16", ("opentine-hook/1",), ("opentine-hook-1",), ("67-hook",),
             T("tests/test_046_hook_steer_resume.py")),
    "admission VSA": ("8.17", (), ("opentine-admission-policy-1",), ("61-vsa",),
                      T("tests/test_046_trust_policy_admission.py")),
    "keyless signing time": ("8.12.1", (), (), ("77-keyless-tsa",), CONFORM),
}  # fmt: skip

#: Repository internals: the pyz verifies exported files and never opens a repository.
STORAGE = (
    "15-links", "15b-metrics", "15c-graph", "15d-load", "16-bounds", "22-layout", "24-refs",
    "26-reflog", "27-shallow", "28-pack", "29-localpack", "99-repair",
)  # fmt: skip
WRITER = ("14-redaction",)

#: Kinds in the tree with no conformance family yet (0.49 adds tests, no kind).
DEFERRED = {
    "tine-verify-report/2": "signed verify reports (8.1, 8.7): no vector family",
    "tine-custody/1": "custody records (8.4, 8.9): no vector family",
    "replay/v1": "the in-toto replay predicate (8.8): no vector family",
    "TINEAES6": "remote at-rest sealing (Part 11): no vector family",
    "opentine-line-attribution/1": "git-note attribution records: fixture tests only",
    "tine-cost-statement/1": "optionally signed cost statements: no vector family",
}

#: Schemas that describe no stored or exchanged kind (CLI outputs, local config, imports).
NOT_KINDS = (
    "agent-trace-0.1", "opentine-merge-gates-1", "opentine-plugin-allow-1", "tine-ai-share-1",
    "tine-assurance-1", "tine-blame-1", "tine-ci-gate-1", "tine-experts-1", "tine-help-1",
    "tine-list-page-1", "tine-redaction-rules-1", "tine-repo-show-1", "tine-search-results-1",
    "tine-share-1", "tine-verify-dataset-1", "tine-watch-1",
)  # fmt: skip
DEFERRED_SCHEMAS = {
    "tine-verify-report-2": "tine-verify-report/2",
    "opentine-line-attribution-1": "opentine-line-attribution/1",
    "tine-cost-statement-1": "tine-cost-statement/1",
}
#: Backticked SPEC heading words that are not kinds (capabilities, commands, fields).
NOT_KIND_NAMES = (
    "caps.project", "caps.social_export", "caps.reviews", "caps.coord", "recall",
    "tine witness serve", "tine-experts/1", "/1", "upgraded_from",
)  # fmt: skip

#: CONFORM families the pyz checks only as whole files (the .tine verifier of
#: tests/test_039_pyz_verifier.py, test_040_tine_v5.py, test_041_post_quantum.py),
#: not case by case: the op-level answers below are 0.49 work. May only shrink.
PYZ_FILE_LEVEL = {
    "31-artifact-v2": "artifact.parse as an op",
    "35-integrity": "integrity.digest/verify as ops (test_039 runs the files)",
    "42-signing": "sig.message as an op",
    "47-verdict": "sig.verify verdict fields as an op",
    "51-compat": "the compat fixtures through the ops",
}

#: Verifier/reader ops in CONFORM families the pyz does not answer op-for-op yet.
#: The pyz verifies these kinds as whole files (tests/test_039_pyz_verifier.py,
#: test_040_tine_v5.py, test_041_post_quantum.py); the op-level answers are 0.49 work.
PYZ_OP_GAPS = {
    "text.validate": "lone-surrogate scan of raw text",
    "artifact.parse": "strict .tine JSON reader, as an op",
    "integrity.digest": "v2 integrity digest, as an op",
    "integrity.verify": "v2 integrity verdict fields, as an op",
    "sig.message": "signed-message bytes per scheme, as an op",
    "sig.verify": "full verdict fields (key_id, signer, signed_at), as an op",
    "object.load": "repository object load (51-compat)",
}
