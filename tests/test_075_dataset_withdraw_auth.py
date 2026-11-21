"""0.75 review: a withdrawal counts only from the run's contributor or a pinned curator."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _containment_records as records
from opentine import _dataset_claims as dc
from opentine import _dataset_version as dv
from opentine import _dataset_withdraw as wd
from tests.dataset_contrib_helpers import annotate as _annotate
from tests.dataset_contrib_helpers import pin_contributor
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_dataset_curate import (  # noqa: F401
    AT,
    CURATOR,
    OPTIMIZER,
    STRANGER,
    _pin,
    _run,
    keys_fixture,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CONTRIBUTOR = Ed25519PrivateKey.from_private_bytes(b"\x76" * 32)


def annotate(repo, run, key=CONTRIBUTOR):
    return _annotate(repo, run, key)


def _raw(repo, run, key, reason="privacy"):
    """A withdrawal record signed by *key*, bypassing the signing-time refusal."""
    claim = {"convention": wd.CONVENTION, "run": run, "reason": reason,
             "contributor": records.fingerprint(key), "withdrawn_at": AT}  # fmt: skip
    return records.record(repo, run, claim, key, f"{wd.HOLD}{run}")


def test_a_stranger_withdrawal_of_a_contributed_run_is_ignored(repo):
    _pin(repo)
    run = _run(repo, 1)
    annotate(repo, run)
    with pytest.raises(PermissionError, match="contributor"):
        wd.withdraw(repo, run, STRANGER, "privacy", AT)
    _raw(repo, run, STRANGER)
    assert dv.withdrawals(repo) == {}
    (row,) = wd.withdrawals(repo)
    assert row["state"].startswith("unverified")
    claim = {"convention": dc.WITHDRAWAL, "run": run, "reason": "privacy",
             "contributor": records.fingerprint(STRANGER), "at": AT}  # fmt: skip
    records.record(repo, run, claim, STRANGER, f"{dv.HOLD}withdrawal:{run}")
    assert dv.withdrawals(repo) == {}


def test_an_unannotated_run_cannot_be_withdrawn_by_an_unpinned_key(repo):
    run = _run(repo, 1)
    with pytest.raises(PermissionError):
        wd.withdraw(repo, run, STRANGER, "privacy", AT)
    _raw(repo, run, STRANGER)
    assert dv.withdrawals(repo) == {}


def test_the_contributor_key_withdrawal_is_honoured(repo):
    _pin(repo)
    run = _run(repo, 1)
    annotate(repo, run)
    with pytest.raises(PermissionError):  # an unpinned annotating key is no contributor
        wd.withdraw(repo, run, CONTRIBUTOR, "consent-withdrawn", AT)
    pin_contributor(repo, CONTRIBUTOR)
    record = wd.withdraw(repo, run, CONTRIBUTOR, "consent-withdrawn", AT)
    assert dv.withdrawals(repo) == {run: record}
    out = dv.curate(repo, "train", "all", CURATOR, AT)
    assert out["claim"]["withdrawn"] == [run]


def test_two_pinned_annotating_keys_refuse_a_new_withdrawal(repo):
    _pin(repo)
    pin_contributor(repo, CONTRIBUTOR)
    pin_contributor(repo, STRANGER)
    run = _run(repo, 1)
    annotate(repo, run)
    annotate(repo, run, STRANGER)
    for key in (CONTRIBUTOR, STRANGER):
        with pytest.raises(PermissionError):
            wd.withdraw(repo, run, key, "privacy", AT)


def test_a_second_annotating_key_makes_the_contributor_ambiguous(repo):
    _pin(repo)
    pin_contributor(repo, CONTRIBUTOR)
    run = _run(repo, 1)
    annotate(repo, run)
    annotate(repo, run, STRANGER)
    _raw(repo, run, STRANGER)
    assert dv.withdrawals(repo) == {}


def test_a_curator_takedown_is_honoured_and_needs_a_reason_category(repo):
    _pin(repo)
    run = _run(repo, 1)
    annotate(repo, run)
    claim = {"convention": dc.WITHDRAWAL, "run": run, "reason": "free text",
             "contributor": records.fingerprint(CURATOR), "at": AT}  # fmt: skip
    records.record(repo, run, claim, CURATOR, f"{dv.HOLD}withdrawal:{run}")
    assert dv.withdrawals(repo) == {}
    record = wd.withdraw(repo, run, CURATOR, "licence", AT)
    assert dv.withdrawals(repo) == {run: record}


def test_an_optimizer_withdrawal_is_refused_even_as_the_annotating_key(repo):
    _pin(repo)
    run = _run(repo, 1)
    annotate(repo, run, OPTIMIZER)
    with pytest.raises(PermissionError, match="optimizer"):
        wd.withdraw(repo, run, OPTIMIZER, "privacy", AT)
    _raw(repo, run, OPTIMIZER)
    assert dv.withdrawals(repo) == {}
