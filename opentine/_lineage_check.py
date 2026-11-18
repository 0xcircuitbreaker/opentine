"""``tine lineage check VARIANT``: walk a variant's ancestry, refuse on missing evidence.

The check reads only a lineage folder (:mod:`opentine._lineage`) as a mapping of
relative path to bytes, so the same function runs over a folder on disk and
over the shared fixture ``tests/data/lineage_check.json``, which the TS port
(``ts/verifier/src/lineage.ts``) answers identically. Every variant reachable
through ``parents`` is checked; each finding names the variant it is about:

``lineage.variant-unknown``   VARIANT has no record in the folder;
``lineage.record-invalid``    a record is malformed, is not Ed25519-signed by its
                              ``signer``, names another variant id than its
                              artifacts give, or targets another run;
``lineage.parent-missing``    a parent has no record;
``lineage.cycle``             the ancestry returns to a variant on the path;
``lineage.evidence-missing``  a justifying eval is absent, its verdicts do not
                              hash to ``verdicts_sha256``, a verdict is unsigned,
                              does not verify, repeats an item or scores another
                              run than the mutation run, or a variant with
                              parents names no eval;
``lineage.decision-mismatch`` the cited promotion decision is absent, unsigned,
                              not an ``opentine.promotion-decision/1`` promote of
                              the mutation run, under another policy, or cites
                              none of the variant's evals.

These codes are ``tine lineage check`` output only: ``tine verify`` and the pyz
do not emit them.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from opentine._lineage import (
    ARTIFACTS,
    CONVENTION,
    DIGEST_RE,
    HEX_RE,
    LOOP_RE,
    RUN_RE,
    read_folder,
    variant_id,
)

DECISION = "opentine.promotion-decision/1"
_CLAIM = {"convention", "variant", "artifacts", "parents", "mutation_run", "evals", "selector",
          "decision", "policy", "loop"}  # fmt: skip


def _unique(pairs: list) -> dict:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")  # one reader, one meaning: no last-wins laundering
    return dict(pairs)


def _loads(raw: bytes | str) -> Any:
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    return json.loads(text, object_pairs_hook=_unique)


def _finding(code: str, variant: str, detail: str) -> dict[str, str]:
    return {"code": f"lineage.{code}", "variant": variant, "detail": detail}


def _signed(payload: Any) -> bool:
    """Ed25519-signed, verifying under its embedded key, and that key is the signer."""
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import verify_attestation

    block = payload.get("signature") if isinstance(payload, dict) else None
    if not isinstance(block, dict) or block.get("alg") != "ed25519":
        return False
    raw = block.get("public_key")
    if not (isinstance(raw, str) and HEX_RE.fullmatch(raw)):
        return False
    if key_fingerprint(bytes.fromhex(raw)) != payload.get("signer"):
        return False
    return verify_attestation(payload, trust_embedded=True).ok


def _shape(claim: Any, variant: str) -> str | None:
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return f"not an {CONVENTION} claim"
    if set(claim) != _CLAIM:
        return "the claim's fields are not the convention's"
    arts = claim["artifacts"]
    good = all(
        isinstance(v, str) and DIGEST_RE.fullmatch(v) for v in getattr(arts, "values", list)()
    )
    if not (isinstance(arts, dict) and arts and set(arts) <= set(ARTIFACTS) and good):
        return "artifacts must map code_tree/prompt/config/weights to sha256: digests"
    if claim["variant"] != variant or variant_id(arts) != variant:
        return "the variant id is not the digest of its artifacts"
    parents, evals = claim["parents"], claim["evals"]
    if not (isinstance(parents, list) and all(isinstance(p, str) and DIGEST_RE.fullmatch(p)
                                              for p in parents)):  # fmt: skip
        return "parents must be sha256: variant ids"
    if not (isinstance(evals, list) and all(
            isinstance(e, dict) and set(e) == {"eval", "verdicts_sha256"}
            and isinstance(e["eval"], str) and DIGEST_RE.fullmatch(e["eval"])
            and isinstance(e["verdicts_sha256"], str) and HEX_RE.fullmatch(e["verdicts_sha256"])
            for e in evals)):  # fmt: skip
        return "evals must be {eval, verdicts_sha256} rows"
    if not (isinstance(claim["mutation_run"], str) and RUN_RE.fullmatch(claim["mutation_run"])):
        return "mutation_run must be a run:sha256: oid"
    cited = claim["decision"]
    if cited is not None and not (isinstance(cited, dict) and set(cited) == {"sha256"}
                                  and isinstance(cited["sha256"], str)
                                  and HEX_RE.fullmatch(cited["sha256"])):  # fmt: skip
        return "decision must be null or {sha256}"
    policy = claim["policy"]
    if policy is not None and not (isinstance(policy, str) and HEX_RE.fullmatch(policy)):
        return "policy must be null or 64 hex"
    if not isinstance(claim["selector"], str):
        return "selector must be text"
    loop = claim["loop"]
    if loop is not None and not (isinstance(loop, str) and LOOP_RE.fullmatch(loop)):
        return "loop must be null or a loop id"
    return None


def _eval_problem(files: dict[str, bytes], row: dict[str, str], run: str) -> str | None:
    from opentine import _eval_verdict as verdicts
    from opentine._eval_run import PINNED, eval_id

    raw = files.get(f"evals/{row['eval'][7:]}.jsonl")
    if raw is None:
        return f"eval {row['eval']} is absent"
    if hashlib.sha256(raw).hexdigest() != row["verdicts_sha256"]:
        return f"eval {row['eval']}: the verdicts do not hash to verdicts_sha256"
    lines = [line for line in raw.decode("utf-8", "replace").split("\n") if line.strip()]
    if not lines:
        return f"eval {row['eval']} has no verdicts"
    seen: set[Any] = set()
    for number, line in enumerate(lines, 1):
        try:
            verdict = _loads(line)
            verdicts.verify(verdict)
            ok = verdict["eval"] == row["eval"] == eval_id({k: verdict[k] for k in PINNED})
        except (verdicts.EvalVerdictError, ValueError, KeyError, TypeError):
            ok = False
        if not ok:
            return f"eval {row['eval']}: verdict {number} is unsigned or does not verify"
        if verdict["run"] != run:
            return f"eval {row['eval']}: verdict {number} scores another run than {run}"
        if verdict["item"] in seen:
            return f"eval {row['eval']}: verdict {number} repeats an item"
        seen.add(verdict["item"])
    return None


def _decision_problem(files: dict[str, bytes], claim: dict[str, Any]) -> str | None:
    digest = claim["decision"]["sha256"]
    raw = files.get(f"decisions/{digest}.json")
    if raw is None or hashlib.sha256(raw).hexdigest() != digest:
        return f"decision {digest} is absent"
    try:
        document = _loads(raw)
    except ValueError:
        return f"decision {digest} is not JSON"
    if not _signed(document):
        return f"decision {digest} is not signed by its signer"
    said = document.get("claim")
    if not isinstance(said, dict) or said.get("schema") != DECISION:
        return f"decision {digest} is not an {DECISION} claim"
    if said.get("action") != "promote" or said.get("candidate") != claim["mutation_run"]:
        return f"decision {digest} does not promote {claim['mutation_run']}"
    if document.get("target_id") != claim["mutation_run"]:
        return f"decision {digest} is not on {claim['mutation_run']}"
    if claim["policy"] is not None and said.get("policy_sha256") != claim["policy"]:
        return f"decision {digest} was made under another policy"
    inputs = said.get("inputs") if isinstance(said.get("inputs"), list) else []
    rows = [i for i in inputs if isinstance(i, dict) and isinstance(i.get("digest"), dict)]
    cited = {(i.get("uri"), i["digest"].get("sha256")) for i in rows}
    if not any((f"eval:{e['eval']}", e["verdicts_sha256"]) in cited for e in claim["evals"]):
        return f"decision {digest} cites none of the variant's evals"
    return None


def _node(files: dict[str, bytes], variant: str, out: list) -> list[str] | None:
    """Check one record; its parents, or None when it is absent or invalid."""
    raw = files.get(f"variants/{variant[7:]}.json")
    if raw is None:
        return None
    try:
        payload = _loads(raw)
    except ValueError:
        out.append(_finding("record-invalid", variant, "the record is not JSON"))
        return []
    claim = payload.get("claim") if isinstance(payload, dict) else None
    problem = _shape(claim, variant)
    if problem is None and payload.get("target_id") != claim["mutation_run"]:
        problem = "the attestation does not target the mutation run"
    if problem is None and not _signed(payload):
        problem = "the record is not Ed25519-signed by its signer"
    if problem is not None:
        out.append(_finding("record-invalid", variant, problem))
        return []
    if claim["parents"] and not claim["evals"]:
        out.append(_finding("evidence-missing", variant, "a derived variant names no eval"))
    for row in claim["evals"]:
        found = _eval_problem(files, row, claim["mutation_run"])
        if found:
            out.append(_finding("evidence-missing", variant, found))
    if claim["decision"] is not None:
        found = _decision_problem(files, claim)
        if found:
            out.append(_finding("decision-mismatch", variant, found))
    return list(claim["parents"])


def check(files: dict[str, bytes], variant: str) -> dict[str, Any]:
    """``{ok, variant, ancestors, findings}``; iterative depth-first, parents in order."""
    out: list[dict[str, str]] = []
    if not (isinstance(variant, str) and DIGEST_RE.fullmatch(variant)):
        raise ValueError("VARIANT must be a sha256:HEX variant id")
    if f"variants/{variant[7:]}.json" not in files:
        out.append(_finding("variant-unknown", variant, "no record names this variant"))
        return {"ok": False, "variant": variant, "ancestors": [], "findings": out}
    state: dict[str, str] = {}
    order: list[str] = []
    stack: list[tuple[str, list[str], int]] = []

    def enter(node: str) -> None:
        state[node] = "open"
        order.append(node)
        stack.append((node, _node(files, node, out) or [], 0))

    enter(variant)
    while stack:
        node, parents, index = stack[-1]
        if index == len(parents):
            state[node] = "done"
            stack.pop()
            continue
        stack[-1] = (node, parents, index + 1)
        parent = parents[index]
        if f"variants/{parent[7:]}.json" not in files:
            out.append(_finding("parent-missing", node, f"parent {parent} has no record"))
        elif state.get(parent) == "open":
            out.append(_finding("cycle", node, f"parent {parent} is its own ancestor"))
        elif parent not in state:
            enter(parent)
    out.sort(key=lambda f: (f["variant"], f["code"], f["detail"]))
    return {"ok": not out, "variant": variant, "ancestors": order[1:], "findings": out}


__all__ = ["check", "read_folder"]
