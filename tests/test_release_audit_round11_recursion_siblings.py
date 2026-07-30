"""Round 11: the remaining unbounded walks over caller data, on every interpreter.

Round 10 bounded ``_canon._jsonable``, ``_canon_redact._redact`` and
``_jsonsafe.json_safe`` and then *reported* four siblings of the same class it
could not touch. This file closes three of them — ``redaction.redact_value``,
``harnesses._types._jsonable`` and ``billing._immutable.freeze``/``thaw`` — plus
two more the sweep for those turned up in the same modules:
``harnesses._types.parse_json_event`` (``json.loads`` recurses in C, and how much
of the recursion budget a C call spends changed in 3.12) and the C comparison of a
frozen billing container.

The class is not "a deep value crashes". It is "*where* it crashes depends on the
interpreter", which is why a test that only checks "depth 600 is refused" passes on
3.12 with the bug in place — how three rounds of fixes each closed one instance and
left the class. So the assertions here are structural: the frame cost per nesting
level (an equality, not a bound), the single shared refusal, and — the round-11
lesson — that the bound leaves room for everything done to the value *after* the
walk, so the crash is eliminated rather than relocated to ``==``.

Measured maxima before the fix (binary search, per interpreter):

===============================  ======  =========  ==============================
walk                             3.11    3.12+      why they differ
===============================  ======  =========  ==============================
redact_value (dicts)             992     993        no bound at all, either one
redact_value (lists)             497     995        list comprehension frame
redact_value (tuples)            497     497        genexpr, never inlined
harnesses _jsonable              496     995        dict/list comprehension frames
freeze (mappings)                495     994        dict comprehension frame
freeze (lists)                   330     497        genexpr *inside* tuple.__new__
thaw                             495     993/994    comprehension frames
parse_json_event                 990     >=8192     C got its own budget in 3.12
_FrozenList/proxy ``==``         331     997        C compare + a Python __eq__
===============================  ======  =========  ==============================
"""

from __future__ import annotations

import ast
import inspect
import json
import time
from pathlib import Path

import pytest

from opentine._canon import _canonical_bytes
from opentine._canon_redact import MAX_CANONICAL_DEPTH
from opentine.billing._immutable import MAX_FROZEN_DEPTH, freeze, thaw
from opentine.billing.catalog import CatalogError, PricingCatalog
from opentine.billing.types import RateCard
from opentine.harnesses.base import _jsonable as harness_jsonable
from opentine.harnesses.base import parse_json_event
from opentine.kernel import MAX_JSON_DEPTH
from opentine.redaction import redact_blob, redact_value
from opentine.repo import Repo

PACKAGE = Path(__file__).resolve().parents[1] / "opentine"

#: The modules this round owns. Every walk in them must be clean, not tolerated.
OWNED = ("redaction.py", "_redact_pem.py", "harnesses/_types.py", "billing/_immutable.py")

#: Recursion units a *comparison* of a frozen container costs per nesting level on
#: 3.11, measured: ``_FrozenList.__eq__``'s Python frame plus the C tuple compare,
#: which is why the maximum there is 331 levels and not ~500.
COMPARISON_UNITS_PER_LEVEL = 3


def wrap_dicts(levels: int, leaf: object = 1) -> object:
    value = leaf
    for _ in range(levels):
        value = {"n": value}
    return value


def wrap_lists(levels: int, leaf: object = 1) -> object:
    value = leaf
    for _ in range(levels):
        value = [value]
    return value


def wrap_tuples(levels: int, leaf: object = 1) -> object:
    value = leaf
    for _ in range(levels):
        value = (value,)
    return value


class _DictProbe(dict):
    """Records the Python frame depth at which a walk reaches the deepest mapping."""

    frames = 0

    def items(self):  # type: ignore[override]
        _DictProbe.frames = len(inspect.stack(0))
        return super().items()


class _ListProbe(list):
    frames = 0

    def __iter__(self):
        _ListProbe.frames = len(inspect.stack(0))
        return super().__iter__()


class _TupleProbe(tuple):
    frames = 0

    def __iter__(self):
        _TupleProbe.frames = len(inspect.stack(0))
        return super().__iter__()


WALKS = (
    ("redact_value", redact_value, _DictProbe, wrap_dicts),
    ("redact_value", redact_value, _ListProbe, wrap_lists),
    ("redact_value", redact_value, _TupleProbe, wrap_tuples),
    ("harnesses._jsonable", harness_jsonable, _DictProbe, wrap_dicts),
    ("harnesses._jsonable", harness_jsonable, _ListProbe, wrap_lists),
    ("freeze", freeze, _DictProbe, wrap_dicts),
    ("freeze", freeze, _ListProbe, wrap_lists),
    ("freeze", freeze, _TupleProbe, wrap_tuples),
    ("thaw", thaw, _DictProbe, wrap_dicts),
    ("thaw", thaw, _TupleProbe, wrap_tuples),
)


def test_every_walk_over_caller_data_costs_exactly_one_frame_per_nesting_level():
    # The mechanism behind the whole class, measured rather than assumed. A
    # comprehension gets its own frame before 3.12 (PEP 709 inlined them there) and
    # a generator expression gets one on *every* version, so a walk that recursed
    # inside either cost two frames per level and failed at half the depth on the
    # support floor — 3.11 raising RecursionError where 3.12 recorded the same value
    # happily. Pinned as an equality: "<= 2" would let a comprehension back in.
    for name, walk, probe, build in WALKS:
        walk(build(40, probe([1]) if probe is not _DictProbe else probe(a=1)))
        shallow = probe.frames
        walk(build(140, probe([1]) if probe is not _DictProbe else probe(a=1)))
        per_level = (probe.frames - shallow) / 100
        assert per_level == 1, f"{name} costs {per_level} frames per level for {probe.__name__}"


def test_no_walk_in_these_modules_recurses_inside_a_comprehension():
    # The structural rule that keeps the matrix aligned, scoped to the modules this
    # round owns and asserted as *zero*, not as a tolerated set: round 10's sweep
    # listed these very functions as known-tolerated, and a tolerance entry silently
    # permits a new comprehension in the same function forever.
    found: set[tuple[str, str]] = set()
    for name in OWNED:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            comprehensions = (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp)
            for item in ast.walk(node):
                if not isinstance(item, comprehensions):
                    continue
                calls = {
                    call.func.id
                    for call in ast.walk(item)
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                }
                if node.name in calls:
                    found.add((name, node.name))
    assert found == set(), f"recursion inside a comprehension diverges the matrix: {sorted(found)}"


def test_each_walk_carries_an_explicit_depth_bound():
    # Every recursive function in these modules must refuse by *depth*, not by
    # running out of stack: an AST check that the guard exists, so deleting the
    # check while leaving the loops (the shape that made this pass on 3.12) fails.
    guarded: set[tuple[str, str]] = set()
    for name in OWNED:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            recursive = any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == node.name
                for call in ast.walk(node)
            )
            compares = {
                compare.left.id
                for compare in ast.walk(node)
                if isinstance(compare, ast.Compare) and isinstance(compare.left, ast.Name)
            }
            if recursive:
                assert "_depth" in compares, f"{name}::{node.name} recurses with no depth bound"
                guarded.add((name, node.name))
    assert guarded == {
        ("redaction.py", "redact_value"),
        ("harnesses/_types.py", "_jsonable"),
        ("billing/_immutable.py", "freeze"),
        ("billing/_immutable.py", "thaw"),
    }


def test_the_write_side_walks_reuse_the_shared_bound_rather_than_inventing_one():
    # redact_value runs immediately *after* _redact over the same value on the v3
    # write path, so round 10's bound is not the boundary here — it still sees
    # everything _redact admitted, which is exactly MAX_CANONICAL_DEPTH levels. The
    # harness walk hands its result to _canon._jsonable next, so it shares the
    # number too: one refusal depth for the whole write side.
    for walk in (redact_value, harness_jsonable):
        assert walk(wrap_dicts(MAX_CANONICAL_DEPTH)) == wrap_dicts(MAX_CANONICAL_DEPTH)
        with pytest.raises(ValueError, match="nesting or structure"):
            walk(wrap_dicts(MAX_CANONICAL_DEPTH + 1))


def test_a_value_too_deep_is_refused_the_same_way_at_every_container_shape():
    # Shape by shape, because the divergence was per-branch: redact_value's dict
    # branch was already a statement loop while its list branch was a comprehension
    # (497 vs 995) and its tuple branch a generator expression (497 on *both*), so
    # a caller could get a RecursionError from one shape and a refusal from another
    # on the same interpreter.
    for build in (wrap_dicts, wrap_lists, wrap_tuples):
        with pytest.raises(ValueError, match="nesting or structure"):
            redact_value(build(MAX_CANONICAL_DEPTH + 1))
    for build in (wrap_dicts, wrap_lists):
        with pytest.raises(ValueError, match="nesting or structure"):
            harness_jsonable(build(MAX_CANONICAL_DEPTH + 1))
    for build in (wrap_dicts, wrap_lists, wrap_tuples):
        with pytest.raises(ValueError, match="nesting or structure"):
            freeze(build(MAX_FROZEN_DEPTH + 1))
    for build in (wrap_dicts, wrap_tuples):
        with pytest.raises(ValueError, match="nesting or structure"):
            thaw(build(MAX_FROZEN_DEPTH + 1))
    # And the shapes below each bound still walk, so the bound refuses depth and
    # not the shape.
    assert redact_value(wrap_tuples(64)) == wrap_tuples(64)
    assert harness_jsonable(wrap_lists(64)) == wrap_lists(64)
    assert thaw(freeze(wrap_lists(64))) == wrap_lists(64)


def test_a_cyclic_container_is_refused_by_every_walk_instead_of_the_stack():
    # A self-referential container is infinitely deep, so the depth bound is also
    # what turns the one crash reachable with *shallow* data into a refusal. A
    # pricing catalog cannot hold a cycle, but a caller-built RateCard can.
    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    for walk in (redact_value, harness_jsonable, freeze):
        for value in (cyclic_dict, cyclic_list):
            with pytest.raises(ValueError, match="nesting or structure"):
                walk(value)
    with pytest.raises(ValueError, match="nesting or structure"):
        thaw(cyclic_dict)


def test_the_billing_bound_leaves_room_for_every_operation_on_a_frozen_value():
    # The round-11 lesson, and the reason billing's bound is tighter than the shared
    # one rather than equal to it. Freezing is not the last thing done to the
    # result: comparing two frozen values recurses in C through _FrozenList.__eq__
    # and MappingProxyType, and on 3.11 a C call spends from the same 1000-unit
    # budget a Python frame does — measured maximum 331 levels there against ~997 on
    # 3.12+. Bounding freeze at 768 would have handed back a card that cannot be
    # compared on the support floor: the interpreter-dependent RecursionError would
    # have moved from freeze to ==, which is precisely how the previous three rounds
    # each closed an instance and left the class. So every operation billing
    # performs on a frozen value must fit at the bound, on every interpreter.
    assert MAX_FROZEN_DEPTH == MAX_CANONICAL_DEPTH // COMPARISON_UNITS_PER_LEVEL
    assert MAX_FROZEN_DEPTH < MAX_CANONICAL_DEPTH
    assert MAX_FROZEN_DEPTH * COMPARISON_UNITS_PER_LEVEL + 128 + len(inspect.stack(0)) <= 1000

    deep = wrap_dicts(MAX_FROZEN_DEPTH)
    frozen = freeze(deep)
    assert frozen == freeze(deep)
    assert frozen == deep
    assert thaw(frozen) == deep
    assert json.loads(json.dumps(thaw(frozen))) == deep
    assert _canonical_bytes(thaw(frozen))
    assert repr(frozen)
    listed = freeze(wrap_lists(MAX_FROZEN_DEPTH))
    assert hash(listed) == hash(freeze(wrap_lists(MAX_FROZEN_DEPTH)))
    assert listed == wrap_lists(MAX_FROZEN_DEPTH)


def test_an_untrusted_pricing_catalog_is_refused_typed_and_not_crashed():
    # The reported reachability: a user-supplied catalog is untrusted input, and
    # PricingCatalog.from_dict catches ArithmeticError/AttributeError/KeyError/
    # TypeError/ValueError but not RecursionError — so on 3.11 a deep metadata
    # object escaped as an uncaught RecursionError while 3.12 loaded the catalog
    # without complaint.
    def catalog(depth: int) -> dict[str, object]:
        return {
            "catalog_id": "c",
            "cards": [
                {
                    "id": "p:m",
                    "provider": "p",
                    "model": "m",
                    "rates": {"input": "1"},
                    "metadata": {"deep": wrap_dicts(depth)},
                }
            ],
        }

    with pytest.raises(CatalogError, match="nesting or structure"):
        PricingCatalog.from_dict(catalog(600), verify=False, require_signature=False)
    with pytest.raises(ValueError, match="nesting or structure"):
        RateCard.from_dict(catalog(MAX_FROZEN_DEPTH + 1)["cards"][0])  # type: ignore[index]

    # No over-refusal: an ordinary card still loads, and one nested to the bound
    # loads *and* survives the comparison and serialization that follow.
    loaded = PricingCatalog.from_dict(catalog(3), verify=False, require_signature=False)
    assert loaded.cards[0].metadata["deep"] == wrap_dicts(3)
    at_bound = RateCard.from_dict(catalog(MAX_FROZEN_DEPTH - 1)["cards"][0])  # type: ignore[index]
    assert at_bound == RateCard.from_dict(catalog(MAX_FROZEN_DEPTH - 1)["cards"][0])  # type: ignore[index]
    assert json.dumps(at_bound.to_dict())


def test_repository_put_refuses_a_deep_payload_without_a_recursion_error(tmp_path):
    # The reported public-API repro. Repo.put does not json_safe its payload, so
    # redact_value is on the v3 write path for every object type: at depth 600 this
    # raised RecursionError from redaction.py's list comprehension on 3.11 and a
    # clean typed refusal on 3.12. RecursionError is not a ValueError, so these
    # pytest.raises blocks are themselves the assertion that it is gone.
    repo = Repo.init(tmp_path / "repo")
    for payload in ({"a": wrap_lists(600)}, {"a": wrap_dicts(600)}, {"a": wrap_tuples(600)}):
        with pytest.raises(ValueError):
            repo.put("event", payload)
    with pytest.raises(ValueError, match="nesting or structure"):
        repo.put("event", {"a": wrap_lists(MAX_CANONICAL_DEPTH + 1)})
    assert repo.put("event", {"ok": True, "note": "api_key: sk-abcdefghijklmnopqrst"})
    stored = repo.get(repo.put("event", {"note": "api_key: sk-abcdefghijklmnopqrst"})).payload()
    assert stored["note"] == "api_key: [REDACTED]"


def test_a_harness_event_line_too_deep_to_store_is_text_and_not_a_crash():
    # json.loads recurses in C over nesting, and the share of the recursion budget a
    # C call spends changed in 3.12: an identical subprocess line parsed past 8000
    # levels on 3.12+ and raised an uncaught RecursionError at ~990 on 3.11, where
    # only JSONDecodeError is caught. Every harness that reads JSONL output goes
    # through here, so a broken tool could kill a run on the support floor only.
    # Nothing past the reader's bound can be stored in either format, so beyond it
    # the line is not an event and is recorded as text like any unparseable line.
    inside = MAX_JSON_DEPTH - 1
    assert isinstance(parse_json_event('{"a": ' + "[" * inside + "1" + "]" * inside + "}"), dict)
    for depth in (MAX_JSON_DEPTH + 1, 5000, 20000):
        assert parse_json_event('{"a": ' + "[" * depth + "1" + "]" * depth + "}") is None
    # Flat-but-huge must still parse: the bracket count only *gates* the depth scan,
    # so a line with thousands of shallow objects cannot be mistaken for a deep one.
    flat = '{"a": [' + ",".join(f'{{"i": {i}}}' for i in range(2000)) + "]}"
    assert len(parse_json_event(flat)["a"]) == 2000  # type: ignore[index]
    assert parse_json_event('{"type": "result", "cost": 1}') == {"type": "result", "cost": 1}
    assert parse_json_event("not json") is None


def test_redacting_text_utf8_cannot_encode_says_so_instead_of_naming_a_codec():
    # redaction.redact_value was the raiser behind a bare UnicodeEncodeError: a str
    # holding an unpaired UTF-16 surrogate (what json.loads returns for a truncated
    # \\udXXX escape — a model response sliced mid-emoji) has no UTF-8 spelling, and
    # value.encode("utf-8") reported that as a codec message from inside a walk. The
    # callers that guard a whole payload report the JSON path; this is the backstop
    # for the ones that reach a single value, so no caller emits a codec error.
    for value in ({"note": "a\ud83d"}, {"a\ud83d": "note"}, ["a\udfff"], ("a\ud800",)):
        with pytest.raises(ValueError) as caught:
            redact_value(value)
        assert "unpaired UTF-16 surrogate" in str(caught.value)
        assert "codec" not in str(caught.value)
    # Legal text — including astral-plane characters, which are surrogate *pairs* in
    # UTF-16 and single scalars in UTF-8 — is untouched.
    assert redact_value({"emoji": "hello 🐍", "k": "api_key: sk-abcdefghijklmnopqrst"}) == {
        "emoji": "hello 🐍",
        "k": "api_key: [REDACTED]",
    }
    # And the collision check still fires: two distinct keys must not silently
    # become one because redaction erased what told them apart.
    with pytest.raises(ValueError, match="collapsed distinct object keys"):
        redact_value({"bearer abc12345678": 1, "bearer xyz98765432": 2})


def test_moving_the_pem_scanner_to_a_leaf_did_not_change_what_it_emits():
    # The private-key scanner moved to _redact_pem.py to keep redaction.py inside
    # the 250-line gate. It is byte-for-byte the same scanner — iterative, so a
    # blob's size never touches the stack — and these are the three behaviors the
    # earlier audits paid for: a whole block collapses, a *truncated* block does not
    # swallow the diagnostics after it, and prose that merely follows a marker is
    # not mistaken for key material.
    body = b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ=="
    block = b"-----BEGIN PRIVATE KEY-----\n" + body + b"\n-----END PRIVATE KEY-----"
    assert redact_blob(block) == b"[REDACTED PRIVATE KEY]"
    assert redact_blob(b'{"k": "-----BEGIN PRIVATE KEY-----' + body + b'"}') == (
        b'{"k": "[REDACTED PRIVATE KEY]"}'
    )
    assert body not in redact_blob(b"-----BEGIN RSA PRIVATE KEY-----\n" + body)
    assert redact_blob(b"-----BEGIN OPENSSH PRIVATE KEY----- note: parser saw a marker") == (
        b"[REDACTED PRIVATE KEY] note: parser saw a marker"
    )


def test_a_truncated_key_still_leaks_nothing_when_a_byte_separates_it_from_the_marker():
    # The same defect 4894a3e closed, reachable through two shapes it did not cover:
    # both emit "[REDACTED PRIVATE KEY]" and then every key byte, which reads as
    # redacted and so survives review. The scan started at the byte right after the
    # marker, so a key whose first byte is not base64 was never found -- and a PEM
    # carried inside JSON has exactly that, its line breaks being the two characters
    # "\" and "n". An *encrypted* block is the second: OpenSSL writes RFC 1421
    # headers and one blank line before the body, and a blank line is what tells the
    # scanner the key ended, so it stopped on the separator and emitted the body.
    body = b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ=="
    escaped = b'{"key": "-----BEGIN PRIVATE KEY-----\\n' + body + b'"}'
    assert redact_blob(escaped) == b'{"key": "[REDACTED PRIVATE KEY]"}'
    assert redact_blob(b'-----BEGIN PRIVATE KEY-----"' + body) == b"[REDACTED PRIVATE KEY]"
    encrypted = (
        b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
        b"DEK-Info: AES-128-CBC,0123456789ABCDEF\n\n" + body
    )
    assert redact_blob(encrypted) == b"[REDACTED PRIVATE KEY]"
    assert redact_blob(encrypted + b"\n\nlookup failed\n") == (
        b"[REDACTED PRIVATE KEY]\nlookup failed\n"
    )
    # And nothing that is not key material is swallowed to get there: prose after a
    # marker still fails the length floor, the blank line still ends an *unheadered*
    # body, and a terminated block is unaffected.
    assert redact_blob(b"-----BEGIN PRIVATE KEY----- (see the log)") == (
        b"[REDACTED PRIVATE KEY] (see the log)"
    )
    assert redact_blob(b"-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\n\nkept text") == (
        b"[REDACTED PRIVATE KEY]\nkept text"
    )
    terminated = b"-----BEGIN PRIVATE KEY-----\n" + body + b"\n-----END PRIVATE KEY-----"
    assert redact_blob(terminated) == b"[REDACTED PRIVATE KEY]"


def test_many_unterminated_markers_stay_linear_and_not_quadratic():
    # The linearity rule test_release_audit_round4 holds this module to, on the shape
    # its corpus misses: its 3000 markers share one line, and a marker with no line
    # break after it redacts the whole remainder in a single pass. Spread the same
    # markers over lines and each one searched the entire rest of the blob for an END
    # that is not there -- quadratic in a blob a recorded model response controls,
    # measured at 4.6s for 400KB. Doubling the input must roughly double the time,
    # so a return to the quadratic scan fails here rather than in a user's timeout.
    line = b'    "note": "-----BEGIN PRIVATE KEY----- a-b_c-d_",\n'
    timings = []
    for count in (4000, 8000):
        blob = line * count
        started = time.monotonic()
        assert b"BEGIN PRIVATE KEY" not in redact_blob(blob)
        timings.append(time.monotonic() - started)
    assert timings[1] < 4 * max(timings[0], 0.01), f"scan is superlinear: {timings}"
    assert sum(timings) < 5.0, f"scan is too slow to be linear: {timings}"
