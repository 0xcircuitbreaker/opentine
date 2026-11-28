"""0.91: a pinned ``tripwires`` or ``custody`` section that does not parse fails closed.

A bundle signed by the pinned owner whose section is malformed is never read as
"no section": the tripwire registry is broken and custody copies are refused.
"""

from __future__ import annotations

import pytest

from opentine import _bundle_section
from opentine import _custody_quorum as cq
from opentine import _tripwire_registry as reg
from opentine import _trust_bundle
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import repo_fixture  # noqa: F401
from tests.tripwire_helpers import pin_rule

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

BAD = [{"version": 2}, {"version": 1, "required": "yes"}, [], "x", {"version": 1, "k": 1},
       {"version": 1, "min_serial": -1}, 0]  # fmt: skip


@pytest.fixture
def unvalidated(monkeypatch):
    """Sign and open bundles whose section the validator would refuse (a lenient signer)."""
    monkeypatch.setattr(_trust_bundle, "validate", lambda payload: payload)


@pytest.mark.parametrize("bad", BAD)
def test_a_malformed_tripwires_section_breaks_the_registry(repo, unvalidated, bad):
    pin_rule(repo, tripwires=bad)
    state = reg.current(repo)
    assert state["status"] == "broken"
    assert state["rule"]["required"] is True
    assert any(f["code"] == "fail:tripwire.registry-rule" for f in state["findings"])


@pytest.mark.parametrize("bad", BAD)
def test_a_malformed_custody_section_requires_and_refuses(repo, unvalidated, bad):
    pin_rule(repo, custody=bad)
    found = cq.policy(repo)
    assert found["required"] is True and found["error"]


def test_the_section_reader_raises_on_a_present_but_unparseable_section(repo, unvalidated):
    pin_rule(repo, tripwires={"version": 9})
    with pytest.raises(_bundle_section.SectionError, match="tripwires"):
        _bundle_section.section(repo.path, "tripwires", reg.section_of)


def test_a_wellformed_section_and_an_absent_one_still_read(repo):
    pin_rule(repo, tripwires={"version": 1, "required": False})
    assert reg.rule(repo)["error"] is None
    pin_rule(repo)
    assert cq.policy(repo)["error"] is None
