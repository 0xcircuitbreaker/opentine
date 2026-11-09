"""Vectors for the six pre-cutoff kinds the 0.48 freeze audit left without any (0.50).

``79-verify-report`` (``tine-verify-report/2``, SPEC 8.1, 8.7), ``80-custody``
(``tine-custody/1`` records, 8.4), ``81-replay`` (the in-toto ``replay/v1``
predicate, 8.8), ``82-sealed6`` (the ``TINEAES6`` header, Part 11),
``83-line-attribution`` (``opentine-line-attribution/1``) and
``84-cost-statement`` (``tine-cost-statement/1``). No kind or wire format is
added: every input is a document the CLI already writes, signed here with the
published seeds and a fixed ``signed_at`` so the bytes are stable. Only
``adapter_docs`` answers.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _cost_export, _custody, _line_attrib, _signed_doc, _verify_report_sign
from opentine.intoto import STATEMENT_TYPE, sign_statement
from opentine.kernel import canonical_json
from opentine.remote import _sealed6
from opentine.repository import _tlog
from tests.conformance.cases import ACCEPT, REJECT, B, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER, READER = "verifier", "reader"
SIGNED_AT = "2026-01-01T00:00:00Z"
RUN = "run:sha256:" + "ab" * 32


def _key(name: str = "ed25519_seed") -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _public(name: str = "ed25519_seed") -> str:
    return _key(name).public_key().public_bytes_raw().hex()


def _sign(domain: bytes, body: dict, key: str = "ed25519_seed", signer: str = "alice") -> dict:
    return _signed_doc.sign(domain, body, _key(key), signer=signer, signed_at=SIGNED_AT)


def _case(prefix: str, section: str, op: str, profile: str):
    def make(name, expect, intent, value, reason=None, *, raw: bool = False) -> Case:
        return Case(
            id=f"{prefix}.{name}",
            section=section,
            checklist=(8,),
            op=op,
            profile=profile,
            expect=expect,
            intent=intent,
            input=B(value) if raw else V(value),
            reason=reason,
            requires=() if raw else ("ed25519",),
        )

    return make


# --- 79: tine-verify-report/2 ----------------------------------------------- #

REPORT_BODY = {
    "schema": "tine-verify-report/2",
    "path": "run.tine",
    "verdict": "pass",
    "checks": [{"name": "digest", "outcome": "pass", "reason": "digest.match"}],
}
REPORT = {**REPORT_BODY, "signature": _sign(_verify_report_sign.DOMAIN, REPORT_BODY)}
_r = _case("verify-report", "8.7", "verify-report.verify", VERIFIER)


def _report(report: dict, key: str | None = None) -> dict:
    return {"report": report, "public_key": key}


VERIFY_REPORT = Family(
    "79-verify-report.json",
    "8.7",
    "verify-report",
    (
        _r(
            "tofu",
            ACCEPT,
            "a signed report verifies under its embedded key, as TOFU",
            _report(REPORT),
        ),
        _r(
            "pinned",
            ACCEPT,
            "a signed report verifies under the supplied key",
            _report(REPORT, _public()),
        ),
        _r(
            "wrong-key",
            ACCEPT,
            "a report checked against another key is not evidence",
            _report(REPORT, _public("ed25519_seed_b")),
        ),
        _r(
            "edited-verdict",
            ACCEPT,
            "a verdict changed after signing breaks the signature",
            _report({**REPORT, "verdict": "fail"}),
        ),
        _r(
            "edited-check",
            ACCEPT,
            "a check edited after signing breaks the signature",
            _report({**REPORT, "checks": []}),
        ),
        _r(
            "unsigned",
            ACCEPT,
            "an unsigned /2 report is read but is not evidence",
            _report(REPORT_BODY),
        ),
        _r(
            "v1",
            ACCEPT,
            "a /1 report is never evidence, signed or not",
            _report({**REPORT, "schema": "tine-verify-report/1"}),
        ),
        _r(
            "hmac",
            ACCEPT,
            "a report signature is Ed25519 only",
            _report({**REPORT, "signature": {**REPORT["signature"], "alg": "hmac-sha256"}}),
        ),
    ),
)


# --- 80: tine-custody/1 records --------------------------------------------- #


def _chain(*actions: str) -> list[dict]:
    records, prev = [], None
    for index, action in enumerate(actions):
        full = {
            "action": action,
            "actor": "alice",
            "format": _custody.FORMAT,
            "id": f"{index:016x}",
            "note": "",
            "subject": RUN,
            "time": SIGNED_AT,
            "prev": prev,
        }
        full["signature"] = _sign(_custody.DOMAIN, full)
        records.append(full)
        prev = _tlog.leaf_hash(canonical_json(full)).hex()
    return records


CHAIN = _chain("exported", "received", "verified")
_k = _case("custody", "8.4", "custody.chain", VERIFIER)


def _records(records: Any, key: str | None = None) -> dict:
    return {"records": records, "public_key": key}


def _swap(records: list, index: int, **changes) -> list:
    out = copy.deepcopy(records)
    out[index].update(changes)
    return out


_EXPORT_BODY = {
    "schema": "tine-custody/1",
    "exported_by": "alice",
    "exported_at": "2026-01-01T00:00:00+00:00",
    "opentine_version": "0.50.0",
    "manifest_sha256": "ef" * 32,
    "runs": [{"run_id": RUN, "file": "runs/a.tine", "sha256": "12" * 32}],
}
_EXPORT_KEY = _key().public_key().public_bytes_raw()
EXPORT = {
    **_EXPORT_BODY,
    "signature": {
        "algorithm": "ed25519",
        "public_key": _EXPORT_KEY.hex(),
        "key_fingerprint": "sha256:" + hashlib.sha256(_EXPORT_KEY).hexdigest(),
        "value": _key().sign(_custody.DOMAIN + canonical_json(_EXPORT_BODY)).hex(),
    },
}
_e = _case("custody", "8.4", "custody.record", VERIFIER)

CUSTODY = Family(
    "80-custody.json",
    "8.4",
    "custody",
    (
        _e(
            "record-signed",
            ACCEPT,
            "an evidence folder's signed custody.jsonl record",
            {"record": EXPORT},
        ),
        _e(
            "record-unsigned",
            ACCEPT,
            "an unsigned custody.jsonl record is read, not valid",
            {"record": _EXPORT_BODY},
        ),
        _e(
            "record-edited",
            ACCEPT,
            "a run list edited after signing is not valid",
            {"record": {**EXPORT, "runs": []}},
        ),
        _e(
            "record-other-key",
            ACCEPT,
            "a signature by another key under the embedded one",
            {
                "record": {
                    **EXPORT,
                    "signature": {**EXPORT["signature"], "public_key": _public("ed25519_seed_b")},
                }
            },
        ),
        _e(
            "record-bad-hex",
            ACCEPT,
            "a signature value that is not hex is not valid",
            {"record": {**EXPORT, "signature": {**EXPORT["signature"], "value": "zz"}}},
        ),
        _k("chain", ACCEPT, "three signed records, each chained to the previous", _records(CHAIN)),
        _k(
            "pinned",
            ACCEPT,
            "the chain verifies under the supplied key",
            _records(CHAIN, _public()),
        ),
        _k("empty", ACCEPT, "no records is an empty chain", _records([])),
        _k(
            "wrong-key",
            REJECT,
            "records checked against another key",
            _records(CHAIN, _public("ed25519_seed_b")),
            "custody.bad-signature",
        ),
        _k(
            "edited-action",
            REJECT,
            "an action changed after signing",
            _records(_swap(CHAIN, 1, action="stored")),
            "custody.bad-signature",
        ),
        _k(
            "dropped",
            REJECT,
            "a record dropped from the middle breaks the chain",
            _records([CHAIN[0], CHAIN[2]]),
            "custody.chain-broken",
        ),
        _k(
            "reordered",
            REJECT,
            "records out of order break the chain",
            _records(CHAIN[::-1]),
            "custody.chain-broken",
        ),
        _k(
            "wrong-format",
            REJECT,
            "only opentine-custody/1 records",
            _records(_swap(CHAIN, 0, format="opentine-custody/2")),
            "custody.malformed",
        ),
        _k(
            "not-a-list",
            REJECT,
            "records are a list",
            _records({"0": CHAIN[0]}),
            "custody.malformed",
        ),
    ),
)


# --- 81: the in-toto replay/v1 predicate ------------------------------------ #

PREDICATE = {
    "verifier": {"id": "https://opentine.dev/tine", "version": "0.50.0"},
    "mode": "cache",
    "replay": {
        "replay_id": RUN,
        "second_id": None,
        "fork_point": None,
        "expected_steps": 3,
        "reused_steps": 3,
    },
    "result": {
        "reproduced": True,
        "identity_ok": True,
        "integrity_ok": True,
        "slice_ok": None,
        "ignore_cost_drift": False,
        "structural_drift": [],
        "accounting_drift": [],
    },
    "fidelity": {"level": "exact"},
    "verified_at": SIGNED_AT,
}
STATEMENT = {
    "_type": STATEMENT_TYPE,
    "subject": [{"name": RUN, "digest": {"sha256": "ab" * 32}}],
    "predicateType": "https://opentine.dev/attestation/replay/v1",
    "predicate": PREDICATE,
}
_p = _case("replay", "8.8", "replay.verify", VERIFIER)


def _envelope(statement: dict, key: str = "ed25519_seed") -> dict:
    return sign_statement(statement, _key(key))


def _replay(envelope: Any, key: str = "ed25519_seed") -> dict:
    return {"envelope": envelope, "public_key": _public(key)}


ENVELOPE = _envelope(STATEMENT)
_TAMPERED = {
    **ENVELOPE,
    "payload": base64.b64encode(canonical_json({**STATEMENT, "subject": []})).decode("ascii"),
}

REPLAY = Family(
    "81-replay.json",
    "8.8",
    "replay",
    (
        _p("signed", ACCEPT, "a replay/v1 statement signed by the supplied key", _replay(ENVELOPE)),
        _p(
            "rerun",
            ACCEPT,
            "the rerun mode",
            _replay(_envelope({**STATEMENT, "predicate": {**PREDICATE, "mode": "rerun"}})),
        ),
        _p(
            "wrong-key",
            REJECT,
            "an envelope signed by another key",
            _replay(ENVELOPE, "ed25519_seed_b"),
            "replay.bad-signature",
        ),
        _p(
            "tampered",
            REJECT,
            "a payload changed after signing",
            _replay(_TAMPERED),
            "replay.bad-signature",
        ),
        _p(
            "payload-type",
            REJECT,
            "only in-toto payloads",
            _replay({**ENVELOPE, "payloadType": "text/plain"}),
            "replay.malformed",
        ),
        _p(
            "bad-base64",
            REJECT,
            "a payload that is not base64",
            _replay({**ENVELOPE, "payload": "!"}),
            "replay.malformed",
        ),
        _p(
            "other-predicate",
            REJECT,
            "a statement of another predicate type",
            _replay(_envelope({**STATEMENT, "predicateType": "https://slsa.dev/provenance/v1"})),
            "replay.malformed",
        ),
        _p(
            "bad-mode",
            REJECT,
            "mode is cache or rerun",
            _replay(_envelope({**STATEMENT, "predicate": {**PREDICATE, "mode": "live"}})),
            "replay.malformed",
        ),
        _p(
            "bad-result",
            REJECT,
            "result booleans are booleans",
            _replay(
                _envelope(
                    {
                        **STATEMENT,
                        "predicate": {
                            **PREDICATE,
                            "result": {**PREDICATE["result"], "reproduced": "yes"},
                        },
                    }
                )
            ),
            "replay.malformed",
        ),
    ),
)


# --- 82: the TINEAES6 header ------------------------------------------------ #

_HEAD = _sealed6.SEALED6 + bytes([4]) + b"k-01" + (7).to_bytes(4, "big")
_TAIL = bytes(24 + 16)


def _sealed(flags: int = 0, codec: int = 0, size: int = 5, head: bytes = _HEAD) -> bytes:
    return head + bytes([flags, codec]) + size.to_bytes(8, "big") + _TAIL + b"ciphertext"


_s = _case("sealed6", "11", "sealed6.header", READER)
SEALED6 = Family(
    "82-sealed6.json",
    "11",
    "sealed6",
    (
        _s(
            "plain",
            ACCEPT,
            "a TINEAES6 header: key id, epoch, flags, codec, size",
            _sealed(),
            raw=True,
        ),
        _s("padded", ACCEPT, "the padded flag", _sealed(flags=1, size=1 << 40), raw=True),
        _s(
            "unknown-flag",
            REJECT,
            "a flag bit this version does not define",
            _sealed(flags=2),
            "sealed6.malformed",
            raw=True,
        ),
        _s(
            "other-magic",
            REJECT,
            "the 0.35 TINEAES5 envelope is not TINEAES6",
            b"TINEAES5" + _sealed()[8:],
            "sealed6.malformed",
            raw=True,
        ),
        _s(
            "empty-key-id",
            REJECT,
            "a key id is 1..255 bytes",
            _sealed(head=_sealed6.SEALED6 + bytes([0]) + (7).to_bytes(4, "big")),
            "sealed6.malformed",
            raw=True,
        ),
        _s(
            "non-ascii-key-id",
            REJECT,
            "a key id is ASCII",
            _sealed(head=_sealed6.SEALED6 + bytes([2]) + "é".encode() + (7).to_bytes(4, "big")),
            "sealed6.malformed",
            raw=True,
        ),
        _s(
            "truncated",
            REJECT,
            "no room for the nonce and tag",
            _HEAD + bytes(10),
            "sealed6.malformed",
            raw=True,
        ),
    ),
)


# --- 83: opentine-line-attribution/1 ---------------------------------------- #

_LINES = ["def f():", "    return 1"]
ATTRIBUTION = _line_attrib.sign(
    {
        "schema": _line_attrib.SCHEMA,
        "lines_added": 2,
        "lines_attributed": 2,
        "files": [
            {
                "path": "src/f.py",
                "ranges": [
                    {
                        "start_line": 1,
                        "end_line": 2,
                        "content_hash": _line_attrib.content_hash(_LINES),
                        "run": RUN,
                        "step": "event:sha256:" + "cd" * 32,
                        "seq": 1,
                        "tool": "write",
                        "model": "m",
                    }
                ],
            }
        ],
    },
    _key(),
)
ADDED = {"src/f.py": {"1": _LINES[0], "2": _LINES[1]}}
_a = _case("line-attribution", "8.24", "line-attribution.verify", VERIFIER)


def _attr(record: dict, added: dict = ADDED, key: str | None = None) -> dict:
    return {"record": record, "added": added, "public_key": key}


LINE_ATTRIBUTION = Family(
    "83-line-attribution.json",
    "8.24",
    "line-attribution",
    (
        _a("tofu", ACCEPT, "a signed record whose ranges match the commit", _attr(ATTRIBUTION)),
        _a("pinned", ACCEPT, "under the supplied key", _attr(ATTRIBUTION, key=_public())),
        _a(
            "wrong-key",
            ACCEPT,
            "under another key the signature is not valid",
            _attr(ATTRIBUTION, key=_public("ed25519_seed_b")),
        ),
        _a(
            "edited-line",
            ACCEPT,
            "a line changed since: the range is stale",
            _attr(ATTRIBUTION, {"src/f.py": {"1": _LINES[0], "2": "    return 2"}}),
        ),
        _a(
            "missing-line",
            ACCEPT,
            "a line the commit no longer adds: the range is stale",
            _attr(ATTRIBUTION, {"src/f.py": {"1": _LINES[0]}}),
        ),
        _a(
            "edited-record",
            ACCEPT,
            "a record edited after signing",
            _attr({**ATTRIBUTION, "lines_attributed": 1}),
        ),
        _a(
            "unsigned",
            ACCEPT,
            "an unsigned record reports its ranges only",
            _attr({k: v for k, v in ATTRIBUTION.items() if k != "signature"}),
        ),
    ),
)


# --- 84: tine-cost-statement/1 ---------------------------------------------- #

COST_BODY = {
    "schema": _cost_export.SCHEMA,
    "aggregate": {
        "run_id": "run-cost-0001",
        "total_cost": 0.0125,
        "total_tokens": 1500,
        "input_tokens": 1200,
        "output_tokens": 300,
        "by_model": {"m": 0.0125},
        "by_kind": {"llm": 0.0125},
        "currency": "USD",
    },
}
COST = {**COST_BODY, "signature": _sign(_cost_export.DOMAIN, COST_BODY)}
_c = _case("cost-statement", "8.25", "cost-statement.verify", VERIFIER)


def _cost(doc: dict, expected: dict = COST_BODY, key: str | None = None) -> dict:
    return {"statement": doc, "expected": expected, "public_key": key}


COST_STATEMENT = Family(
    "84-cost-statement.json",
    "8.25",
    "cost-statement",
    (
        _c("tofu", ACCEPT, "a signed statement that matches its run", _cost(COST)),
        _c("pinned", ACCEPT, "under the supplied key", _cost(COST, key=_public())),
        _c("wrong-key", ACCEPT, "under another key", _cost(COST, key=_public("ed25519_seed_b"))),
        _c(
            "other-run",
            ACCEPT,
            "a statement that does not match the run",
            _cost(
                COST, {**COST_BODY, "aggregate": {**COST_BODY["aggregate"], "total_tokens": 1501}}
            ),
        ),
        _c(
            "edited",
            ACCEPT,
            "a cost changed after signing",
            _cost(
                {**COST, "aggregate": {**COST_BODY["aggregate"], "total_cost": 0.0}},
                {**COST_BODY, "aggregate": {**COST_BODY["aggregate"], "total_cost": 0.0}},
            ),
        ),
        _c("unsigned", ACCEPT, "an unsigned statement is never ok", _cost(COST_BODY)),
    ),
)

FAMILIES = (VERIFY_REPORT, CUSTODY, REPLAY, SEALED6, LINE_ATTRIBUTION, COST_STATEMENT)
