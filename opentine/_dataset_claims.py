"""Curated dataset records (0.75): four claim conventions on attestations.

No object kind and no ``tine verify`` code is added; each record is an
**attestation** (an existing object kind) whose claim names its convention
(docs/DATASETS.md):

* ``opentine.dataset-version/1`` -- one signed version of a curated dataset:
  the selection expression, the member runs (each with the digest of its
  content-defined chunks, so no two members share content), the runs dropped
  as duplicates, and the taint filter that was applied;
* ``opentine.dataset-justification/1`` -- a curator's or policy key's signed
  reason to let named tainted runs into one version of one dataset
  (``--include-tainted``; ``for_version`` is the version number it admits them to);
* ``opentine.dataset-withdrawal/1`` -- a contributor's signed request that a
  run leave every later version;
* ``opentine.dataset-tombstone/1`` -- written when a later version drops a
  withdrawn run that an earlier version held.

:func:`check_version` is the offline check of a version: it needs only the
attestation payload (the TS verifier ports it, shared vectors in
``tests/data/dataset_version.json``). It never consults the trust bundle;
whether the signer holds a pinned ``curator`` role is decided with the
repository (:mod:`opentine._dataset_version`).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from opentine.kernel import canonical_json

# Blank text is ASCII whitespace only, the same set as the TS verifier's BLANK:
# str.strip and String.trim disagree on U+001C..U+001F, U+0085 and U+FEFF.
BLANK = re.compile(r"[\t\n\v\f\r ]*")

VERSION = "opentine.dataset-version/1"
JUSTIFICATION = "opentine.dataset-justification/1"
WITHDRAWAL = "opentine.dataset-withdrawal/1"
TOMBSTONE = "opentine.dataset-tombstone/1"
SOURCES = ("integrity-taint", "monitor-verdict", "oversight-reject", "sabotage-task",
           "transcript-flag")  # fmt: skip
CHUNKING = {"scheme": "fastcdc-gear49", "min": 64, "avg": 256, "max": 2048}
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
RUN_RE = re.compile(r"run:sha256:[0-9a-f]{64}")
ATT_RE = re.compile(r"attestation:sha256:[0-9a-f]{64}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
AT_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_VERSION_FIELDS = ("convention", "name", "version", "previous", "selection", "members",
                   "members_digest", "dedup", "taint_filter", "withdrawn", "curator",
                   "created_at")  # fmt: skip
_FILTER_FIELDS = ("mode", "sources", "excluded", "included_tainted", "justification")


def members_digest(members: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(members)).hexdigest()


def _runs(value: Any) -> bool:
    """A sorted list of distinct run ids."""
    return (isinstance(value, list) and all(isinstance(r, str) and RUN_RE.fullmatch(r)
                                            for r in value)
            and value == sorted(set(value)))  # fmt: skip


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _members(members: Any) -> list[str]:
    if not isinstance(members, list) or any(
        not isinstance(m, dict) or set(m) != {"run", "content"} for m in members
    ):
        return ["members are {run, content} objects"]
    runs = [m["run"] for m in members]
    if not _runs(runs):
        return ["members are sorted by run, each run once"]
    content = [m["content"] for m in members]
    if any(not isinstance(c, str) or not DIGEST_RE.fullmatch(c) for c in content):
        return ["member content is a sha256: digest"]
    if len(set(content)) != len(content):
        return ["two members share content: the deduplication does not hold"]
    return []


def _dedup(dedup: Any, members: set[str]) -> list[str]:
    if not isinstance(dedup, dict) or set(dedup) != {"chunking", "candidates", "dropped"}:
        return ["dedup is {chunking, candidates, dropped}"]
    if dedup["chunking"] != CHUNKING:
        return ["dedup chunking is not the fastcdc-gear49 parameters"]
    dropped = dedup["dropped"]
    if not isinstance(dropped, list) or any(
        not isinstance(d, dict) or set(d) != {"run", "same_as"} for d in dropped
    ):
        return ["dropped rows are {run, same_as}"]
    runs = [d["run"] for d in dropped]
    if not _runs(runs) or set(runs) & members:
        return ["dropped runs are sorted, distinct and not members"]
    if any(d["same_as"] not in members for d in dropped):
        return ["a dropped run's same_as is not a member"]
    if not _int(dedup["candidates"]) or dedup["candidates"] < len(members) + len(runs):
        return ["dedup candidates is a count at least members plus dropped"]
    return []


def _filter(flt: Any, members: set[str]) -> list[str]:
    if not isinstance(flt, dict) or set(flt) != set(_FILTER_FIELDS):
        return ["taint_filter has the wrong set of fields"]
    if flt["sources"] != list(SOURCES):
        return ["taint_filter sources are not the five taint sources"]
    if not _runs(flt["excluded"]) or set(flt["excluded"]) & members:
        return ["excluded runs are sorted, distinct and not members"]
    included = flt["included_tainted"]
    if not _runs(included) or not set(included) <= members:
        return ["included_tainted runs are sorted members"]
    if flt["mode"] == "default":
        if included or flt["justification"] is not None:
            return ["the default filter includes no tainted run and has no justification"]
    elif flt["mode"] == "include-tainted":
        just = flt["justification"]
        if not isinstance(just, str) or not ATT_RE.fullmatch(just):
            return ["include-tainted names its justification attestation"]
    else:
        return ["taint_filter mode is default or include-tainted"]
    return []


def check_version(claim: Any) -> list[str]:
    """Problems with *claim* as a dataset version (none: valid)."""
    if not isinstance(claim, dict) or claim.get("convention") != VERSION:
        return [f"not an {VERSION} claim"]
    if set(claim) != set(_VERSION_FIELDS):
        return ["wrong set of fields"]
    if not isinstance(claim["name"], str) or not NAME_RE.fullmatch(claim["name"]):
        return ["name is lower-case letters, digits, dot, underscore and hyphen"]
    if not _int(claim["version"]) or claim["version"] < 1:
        return ["version is a positive integer"]
    previous = claim["previous"]
    if (claim["version"] == 1) != (previous is None) or (
        previous is not None and not (isinstance(previous, str) and ATT_RE.fullmatch(previous))
    ):
        return ["previous is null for version 1 and an attestation id after"]
    if not isinstance(claim["selection"], str) or BLANK.fullmatch(claim["selection"]):
        return ["selection is the expression that chose the candidates"]
    problems = _members(claim["members"])
    if problems:
        return problems
    if claim["members_digest"] != members_digest(claim["members"]):
        return ["members_digest does not match the members"]
    runs = {m["run"] for m in claim["members"]}
    problems = _dedup(claim["dedup"], runs) or _filter(claim["taint_filter"], runs)
    if problems:
        return problems
    if not _runs(claim["withdrawn"]) or set(claim["withdrawn"]) & runs:
        return ["withdrawn runs are sorted, distinct and not members"]
    if not isinstance(claim["curator"], str) or not DIGEST_RE.fullmatch(claim["curator"]):
        return ["curator is a key fingerprint"]
    if not isinstance(claim["created_at"], str) or not AT_RE.fullmatch(claim["created_at"]):
        return ["created_at is YYYY-MM-DDTHH:MM:SSZ"]
    return []


def check_record(claim: Any) -> list[str]:
    """Problems with a justification, withdrawal or tombstone claim (none: valid)."""
    shapes = {
        JUSTIFICATION: ("dataset", "for_version", "runs", "reason", "curator", "at"),
        WITHDRAWAL: ("run", "reason", "contributor", "at"),
        TOMBSTONE: ("dataset", "version", "run", "withdrawal", "curator", "at"),
    }
    kind = claim.get("convention") if isinstance(claim, dict) else None
    if kind not in shapes:
        return ["not a dataset record claim"]
    if set(claim) != {"convention", *shapes[kind]}:
        return ["wrong set of fields"]
    if "dataset" in claim and not (isinstance(claim["dataset"], str)
                                   and NAME_RE.fullmatch(claim["dataset"])):  # fmt: skip
        return ["dataset is a dataset name"]
    number = claim.get("for_version", 1)
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        return ["for_version is a positive version number"]
    if "runs" in claim and (not _runs(claim["runs"]) or not claim["runs"]):
        return ["runs is a non-empty sorted list of distinct run ids"]
    if "run" in claim and not (isinstance(claim["run"], str) and RUN_RE.fullmatch(claim["run"])):
        return ["run is a run id"]
    for field in ("version", "withdrawal"):
        value = claim.get(field, "")
        if field in claim and not (isinstance(value, str) and ATT_RE.fullmatch(value)):
            return [f"{field} is an attestation id"]
    if "reason" in claim and not (isinstance(claim["reason"], str) and claim["reason"].strip()):
        return ["reason is a non-empty string"]
    if not isinstance(claim["at"], str) or not AT_RE.fullmatch(claim["at"]):
        return ["at is YYYY-MM-DDTHH:MM:SSZ"]
    return []


def offline(payload: Any) -> dict[str, Any]:
    """The offline verdict on a version attestation payload (no repository, no trust bundle).

    ``{"ok", "signature", "problems", "members", "excluded"}``; ``signature`` is
    ``verified-tofu`` when the Ed25519 signature holds under the embedded key
    and that key is the payload ``signer`` and the claim's ``curator``.
    """
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    payload = payload if isinstance(payload, dict) else {}
    claim = payload.get("claim")
    problems = check_version(claim)
    target = payload.get("target_id")
    if not (isinstance(target, str) and RUN_RE.fullmatch(target)):
        problems.append("the record does not target a run")
    block = payload.get("signature")
    if not isinstance(block, dict) or block.get("alg") != "ed25519":
        state = "unsigned"
    elif used_key_fingerprint(block) != payload.get("signer"):
        state = "signer-mismatch"
    else:
        result = verify_attestation(payload, trust_embedded=True)
        state = "verified-tofu" if result.ok else "bad-signature"
    if (
        state == "verified-tofu"
        and isinstance(claim, dict)
        and claim.get("curator") != payload.get("signer")
    ):
        state = "curator-mismatch"
    good = isinstance(claim, dict) and not problems
    return {"ok": good and state == "verified-tofu", "signature": state, "problems": problems,
            "members": len(claim["members"]) if good else 0,
            "excluded": len(claim["taint_filter"]["excluded"]) if good else 0}  # fmt: skip


__all__ = ["ATT_RE", "CHUNKING", "JUSTIFICATION", "NAME_RE", "RUN_RE", "SOURCES", "TOMBSTONE",
           "VERSION", "WITHDRAWAL", "check_record", "check_version", "members_digest",
           "offline"]  # fmt: skip
