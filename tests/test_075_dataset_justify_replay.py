"""0.75 review: a taint justification is bound to one dataset version and cannot be replayed."""

from __future__ import annotations

import pytest

from opentine import _dataset_version as dv
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_dataset_curate import (  # noqa: F401
    AT,
    CURATOR,
    _pin,
    _run,
    _seed_taints,
    keys_fixture,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def test_a_justification_for_version_n_does_not_admit_tainted_runs_into_n_plus_1(repo):
    _pin(repo)
    tainted = [_run(repo, i) for i in range(10)]
    _seed_taints(repo, tainted)
    _run(repo, 20)
    just = dv.justify(repo, "train", [tainted[0]], "needed once for a red-team set", CURATOR, AT)
    first = dv.curate(repo, "train", "all", CURATOR, AT, include_tainted=True,
                      justification_id=just)  # fmt: skip
    assert first["claim"]["version"] == 1
    assert first["claim"]["taint_filter"]["included_tainted"] == [tainted[0]]
    with pytest.raises(PermissionError, match="version"):
        dv.curate(repo, "train", "all", CURATOR, AT, include_tainted=True,
                  justification_id=just)  # fmt: skip
    assert [v["version"] for v in dv.versions(repo, "train")] == [1]


def test_the_justification_names_the_version_it_justifies(repo):
    _pin(repo)
    tainted = [_run(repo, i) for i in range(10)]
    _seed_taints(repo, tainted)
    dv.curate(repo, "train", "all", CURATOR, AT)
    just = dv.justify(repo, "train", [tainted[1]], "for version two", CURATOR, AT)
    assert repo.get(just).payload()["claim"]["for_version"] == 2
    out = dv.curate(repo, "train", "all", CURATOR, AT, include_tainted=True,
                    justification_id=just)  # fmt: skip
    assert out["claim"]["version"] == 2 and tainted[1] in out["claim"]["taint_filter"][
        "included_tainted"]  # fmt: skip
