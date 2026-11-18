"""0.58 lineage signer trust and resource cap.

Before 0.58 ``tine lineage check`` proved who signed a justifying eval, not that
the signer was trusted, so a loop could sign its own evals with its optimizer
key and record a variant that checked ``ok``. With ``.tine/key-roles.toml``
(0.57) naming scorer and optimizer keys, check and why refuse such a variant
with ``lineage.signer-untrusted``; with no roles they report ``unpinned``.
"""

from __future__ import annotations

import json

import pytest

from opentine import _schemas
from opentine._lineage import LineageTooLarge, read_folder, record
from opentine._lineage_check import check
from opentine.repo import Repo
from tests.lineage_helpers import RECORDER, art, trust
from tests.promote_helpers import AT, EVALER, RUN_A, RUN_B, fingerprint, key, make_eval, policy

from .test_059_lineage_graph import tine

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture
def loop(tmp_path):
    """A repo whose loop recorded one variant on an eval it signed itself, one on a scorer's."""
    repo = Repo.init(tmp_path / "r")
    store = repo.path / "lineage"
    root = record(key(RECORDER), run=RUN_A, artifacts=art(0), store=store, at=AT)["variant"]
    own = make_eval(tmp_path / "own", RUN_B, lambda i: True, signer=RECORDER)
    fair = make_eval(tmp_path / "fair", RUN_B, lambda i: i % 3 != 0)
    forged = record(key(RECORDER), run=RUN_B, artifacts=art(1), store=store, parents=[root],
                    evals=[own], at=AT)["variant"]  # fmt: skip
    good = record(key(RECORDER), run=RUN_B, artifacts=art(2), store=store, parents=[root],
                  evals=[fair], at=AT)["variant"]  # fmt: skip
    return tmp_path, repo, store, forged, good


def _roles(repo: Repo, **roles: list[str]) -> None:
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def _check(capsys, repo: Repo, variant: str, *extra: str) -> tuple[int, dict]:
    code, out = tine(capsys, "lineage", "check", variant, "--repo", repo.path.parent.as_posix(),
                     "--json", *extra)  # fmt: skip
    row = json.loads(out)
    _schemas.validate(row, "tine-cli-lineage-1")
    return code, row


def test_a_self_signed_eval_is_refused_when_roles_pin_signers(loop, capsys):
    _, repo, _, forged, good = loop
    _roles(repo, optimizer=[fingerprint(RECORDER)], scorer=[fingerprint(EVALER)])
    code, row = _check(capsys, repo, forged)
    assert code == 1 and row["signers"] == "pinned"
    assert [(f["code"], f["variant"]) for f in row["findings"]] == [
        ("lineage.signer-untrusted", forged)
    ]
    code, row = _check(capsys, repo, good)
    assert code == 0 and row["ok"] and row["signers"] == "pinned"


def test_why_refuses_the_same_forged_variant(loop, capsys):
    _, repo, _, forged, _ = loop
    _roles(repo, optimizer=[fingerprint(RECORDER)], scorer=[fingerprint(EVALER)])
    code, out = tine(capsys, "lineage", "why", forged, "--repo", repo.path.parent.as_posix(),
                     "--json")  # fmt: skip
    row = json.loads(out)
    assert code == 1 and row["signers"] == "pinned"
    assert {f["code"] for f in row["findings"]} == {"lineage.signer-untrusted"}


def test_an_optimizer_key_listed_as_scorer_is_still_untrusted(loop):
    _, _, store, forged, _ = loop
    both = {"eval_signers": [fingerprint(RECORDER)], "optimizer": [fingerprint(RECORDER)]}
    assert [f["code"] for f in check(read_folder(store), forged, both)["findings"]] == [
        "lineage.signer-untrusted"
    ]


def test_the_promotion_policy_pin_narrows_the_scorer_role(loop, capsys):
    base, repo, _, _, good = loop
    _roles(repo, scorer=[fingerprint(EVALER), fingerprint(RECORDER)])
    pin = policy(base, eval_signers=[fingerprint(RECORDER)]).as_posix()
    code, row = _check(capsys, repo, good, "--promotion-policy", pin)
    assert code == 1 and row["findings"][0]["code"] == "lineage.signer-untrusted"


def test_no_roles_file_reports_signers_unpinned(loop, capsys):
    _, repo, _, forged, _ = loop
    code, row = _check(capsys, repo, forged)
    assert code == 0 and row["signers"] == "unpinned"
    code, out = tine(capsys, "lineage", "check", forged, "--repo", repo.path.parent.as_posix())
    assert "warning: eval signers are unpinned" in out


def test_trust_is_plain_data_shared_with_the_fixture(loop):
    _, _, store, forged, good = loop
    files = read_folder(store)
    assert not check(files, forged, trust())["ok"]
    assert check(files, good, trust())["ok"]


def test_a_folder_over_the_file_limit_is_refused_unread(loop, capsys):
    _, repo, store, forged, _ = loop
    count = len(read_folder(store))
    with pytest.raises(LineageTooLarge):
        read_folder(store, max_files=count - 1)
    with pytest.raises(LineageTooLarge):
        read_folder(store, max_bytes=1)
    code, _ = tine(capsys, "lineage", "check", forged, "--repo", repo.path.parent.as_posix(),
                   "--max-files", str(count - 1))  # fmt: skip
    assert code != 0
    code, _ = tine(capsys, "lineage", "check", forged, "--repo", repo.path.parent.as_posix(),
                   "--max-files", str(count))  # fmt: skip
    assert code == 0
