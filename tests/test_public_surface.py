"""The top-level ``opentine`` surface is a declared set, not an accident.

``opentine.core`` has always been the source of the public primitives, but the
package root re-exported only part of it, so ``from opentine import RunDiff``
failed while ``from opentine.core import RunDiff`` worked — a difference no user
could predict from the docs. 0.6.0 closes that gap for the diff, query and
signing names.

Two pins, and both directions matter:

* **Nothing may quietly drop out.** Every name in ``opentine.__all__`` must
  resolve from the package and be the *same object* ``opentine.core`` exports,
  so a re-export cannot rot into a stale copy.
* **Nothing may quietly creep in.** ``opentine.__all__`` must equal
  ``EXPECTED_SURFACE`` exactly. Re-exporting a name is a semver promise; making
  that promise has to be an edit to this file too.

The policy classes and profile helpers are a deliberate *hole*: they are a
larger commitment (a configuration API, not a data type) and are deferred to
0.7.0. ``DEFERRED_TO_0_7_0`` pins that they stay reachable from
``opentine.core`` and stay absent from the root, so "we decided not to yet"
cannot decay into "someone shipped it by accident".
"""

from __future__ import annotations

import opentine
from opentine import core

#: Added at the package root in 0.6.0: the diff, query and signing triples plus
#: the two loose names core exposed and the root did not.
ADDED_IN_0_6_0 = frozenset(
    {
        # diff
        "RunDiff",
        "StepChange",
        "FieldDelta",
        # query
        "Graph",
        "Query",
        "QueryError",
        "parse_query",
        # signing
        "sign_artifact",
        "verify_artifact",
        "SignatureResult",
        "SignatureError",
        # loose
        "FORMAT_VERSION",
        "BudgetBreach",
    }
)

#: Everything the root exported before 0.6.0. Two of these (``MigrationError``,
#: ``migrate_dict``) come from ``opentine.migrations``, not ``core``.
SURFACE_BEFORE_0_6_0 = frozenset(
    {
        "Agent",
        "BillingResult",
        "Budget",
        "BudgetExceeded",
        "CostBreakdown",
        "IntegrityResult",
        "MigrationError",
        "Model",
        "PricingCatalog",
        "RateCard",
        "Recorder",
        "Repo",
        "Run",
        "RunIndex",
        "RunStatus",
        "Step",
        "StepKind",
        "TraceEvent",
        "Usage",
        "__version__",
        "migrate_dict",
        "short_id",
        "step_id",
        "to_otel_genai",
        "to_otel_genai_document",
        "tool_schema",
    }
)

EXPECTED_SURFACE = SURFACE_BEFORE_0_6_0 | ADDED_IN_0_6_0

#: Public from ``opentine.core``, deliberately not from the package root until
#: 0.7.0. Configuration APIs, not data types.
DEFERRED_TO_0_7_0 = frozenset(
    {
        "FilesystemPolicy",
        "NetworkPolicy",
        "PolicySet",
        "PythonPolicy",
        "RedactionPolicy",
        "ShellPolicy",
        "dev_profile",
        "isolated_profile",
        "secure_profile",
    }
)

#: Names the root exports that ``core`` does not, so the gap arithmetic below is
#: exact rather than approximately right.
NOT_FROM_CORE = frozenset({"MigrationError", "migrate_dict", "__version__"})


def test_every_exported_name_resolves_from_the_package():
    missing = [name for name in opentine.__all__ if not hasattr(opentine, name)]
    assert missing == []


def test_the_surface_is_exactly_the_declared_set():
    """Neither reopened nor overgrown: an edit here is the only way to change it."""
    assert set(opentine.__all__) == EXPECTED_SURFACE
    assert len(opentine.__all__) == len(set(opentine.__all__)), "duplicate in __all__"


def test_the_new_names_resolve_and_are_the_core_objects():
    for name in sorted(ADDED_IN_0_6_0):
        assert name in opentine.__all__, name
        assert getattr(opentine, name) is getattr(core, name), name


def test_no_re_export_is_a_stale_copy():
    for name in sorted(EXPECTED_SURFACE - NOT_FROM_CORE):
        assert getattr(opentine, name) is getattr(core, name), name


def test_the_only_gap_left_against_core_is_the_deferred_set():
    gap = set(core.__all__) - set(opentine.__all__)
    assert gap == set(DEFERRED_TO_0_7_0)


def test_the_deferred_names_stay_off_the_root_and_on_core():
    for name in sorted(DEFERRED_TO_0_7_0):
        assert name in core.__all__, name
        assert hasattr(core, name), name
        assert name not in opentine.__all__, name
        assert not hasattr(opentine, name), name


def test_the_added_names_are_the_diff_query_and_signing_families():
    """A shape check, so a future edit cannot fold an unrelated name in here."""
    assert ADDED_IN_0_6_0 <= set(core.__all__)
    assert ADDED_IN_0_6_0 & SURFACE_BEFORE_0_6_0 == set()
    assert ADDED_IN_0_6_0 & DEFERRED_TO_0_7_0 == set()


def test_star_import_matches_all():
    namespace: dict = {}
    exec("from opentine import *", namespace)  # noqa: S102 - the surface under test
    assert set(namespace) - {"__builtins__"} == EXPECTED_SURFACE
