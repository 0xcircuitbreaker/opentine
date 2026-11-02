"""Format v4 (0.26): the JCS corpus, and the v4 ``.tine`` artifact read/write.

The corpus is typed in by hand from RFC 8785 (Appendix B, and the sorting and
escaping examples of section 3.2) and the cyberphone ``es6testfile`` IEEE-754
values. Expected strings are the JCS answers, never computed by opentine: a
disagreement is a finding to report, not a vector to regenerate.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest

from opentine import Run, StepKind, _codec
from opentine._artifact_v4 import read_v4, write_v4
from opentine._format_v4 import ARTIFACT_V4_KIND, FORMAT_ENV, is_v4_artifact
from opentine.kernel import KernelError, canonical_json
from opentine.migrations import MigrationError, migrate_dict

FIXTURES = Path(__file__).parent / "fixtures"

#: (IEEE-754 double as 16 hex digits, the JCS serialization)
IEEE_VECTORS = (
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
)
NON_FINITE = ("7fffffffffffffff", "7ff0000000000000", "fff0000000000000")

#: RFC 8785 3.2.3: keys sort by UTF-16 code units, so U+1F600 (D83D DE00)
#: precedes U+FB33 although its code point is larger.
SORTING = (
    {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
     "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"},  # noqa: E501
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O '
    'With Diaeresis","€":"Euro Sign","\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew '
    'Letter Dalet With Dagesh"}',
)  # fmt: skip
ESCAPES = (
    ('€$\u000f\nA\'B"\\\\"/', '"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"'),
    ("\b\t\n\f\r\x1f\x7f", '"\\b\\t\\n\\f\\r\\u001f\x7f"'),
    ("  ", '"  "'),
)
REFUSED = (
    {"n": 2**53},
    {"n": -(2**53)},
    {"n": 2**64},
    {"k": "\ud800"},
    {"\udc00": 1},
)


def _double(hex_bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(hex_bits))[0]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / "home" / name.lower()))
    monkeypatch.delenv(FORMAT_ENV, raising=False)


def _run(run_id: str = "v4-run") -> Run:
    run = Run(id=run_id)
    run.add_step(StepKind.think, {"q": "hi", "f": 1e20, "x": 0.1}, {"a": [1, 2, "\U0001f600"]})
    run.add_step(StepKind.done, {"text": "ok"}, cost=0.25)
    run.add_tag("demo")
    run.metadata["note"] = "kept"
    return run


# --------------------------------------------------------------------------- #
# Phase 1: the JCS conformance corpus, pinned against kernel.canonical_json
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("bits", "expected"), IEEE_VECTORS, ids=[b for b, _ in IEEE_VECTORS])
def test_ieee_double_serializes_as_jcs(bits: str, expected: str) -> None:
    assert canonical_json(_double(bits)).decode() == expected


@pytest.mark.parametrize("bits", NON_FINITE)
def test_non_finite_double_is_refused(bits: str) -> None:
    with pytest.raises(KernelError):
        canonical_json(_double(bits))


def test_non_bmp_keys_sort_by_utf16_code_units() -> None:
    value, expected = SORTING
    assert canonical_json(value).decode() == expected


@pytest.mark.parametrize(("text", "expected"), ESCAPES)
def test_string_escaping_is_jcs(text: str, expected: str) -> None:
    assert canonical_json(text).decode() == expected


def test_negative_zero_and_safe_integer_edges() -> None:
    assert canonical_json({"z": -0.0, "i": 2**53 - 1, "j": -(2**53 - 1)}) == (
        b'{"i":9007199254740991,"j":-9007199254740991,"z":0}'
    )


@pytest.mark.parametrize("value", REFUSED, ids=["2-53", "neg-2-53", "2-64", "surr-v", "surr-k"])
def test_wide_integers_and_lone_surrogates_are_refused(value) -> None:
    with pytest.raises(KernelError):
        canonical_json(value)


def test_the_canon_v4_vectors_carry_the_hand_typed_jcs_answers() -> None:
    """The generated suite and this corpus must agree byte for byte."""
    family = json.loads(
        (Path(__file__).parents[1] / "docs/conformance/vectors/09-canon-v4.json").read_text()
    )
    outputs = {
        case["id"]: base64.b64decode(case["output"]["bytes_b64"]).decode()
        for case in family["cases"]
        if case["expect"] == "accept"
    }
    for bits, expected in IEEE_VECTORS:
        assert outputs[f"canon.v4.ieee.{bits}"] == '{"n":' + expected + "}"
    assert outputs["canon.v4.key.order-utf16"] == SORTING[1]


# --------------------------------------------------------------------------- #
# Phase 2: the v4 artifact
# --------------------------------------------------------------------------- #


def test_round_trip_preserves_the_run() -> None:
    run = _run()
    back = read_v4(write_v4(run))
    assert back.id == run.id and back.status == run.status
    assert [s.kind for s in back.steps] == [s.kind for s in run.steps]
    assert [s.inputs for s in back.steps] == [s.inputs for s in run.steps]
    assert [s.outputs for s in back.steps] == [s.outputs for s in run.steps]
    assert back.steps[0].inputs["f"] == 1e20 and isinstance(back.steps[0].inputs["f"], float)
    assert back.tags == ["demo"] and back.metadata == {"note": "kept"}
    assert back.total_cost == run.total_cost


def test_run_oid_is_stable_and_equals_the_v3_run_oid(tmp_path: Path) -> None:
    from opentine.repository import Repo

    run = _run()
    first = write_v4(run)
    assert first == write_v4(run)
    assert write_v4(read_v4(first)) == first  # read then write re-addresses nothing
    document = json.loads(first)
    assert document["kind"] == ARTIFACT_V4_KIND and is_v4_artifact(document)
    assert canonical_json(document) == first
    repo = Repo.init(tmp_path / "repo", compression=None)
    assert repo.put_run(run).run_id == document["root"]


def _tamper(raw: bytes, mutate) -> bytes:
    document = json.loads(raw)
    mutate(document)
    return json.dumps(document).encode()


def _event(document: dict) -> dict:
    return next(e for oid, e in document["objects"].items() if oid.startswith("event:"))


def _blob(document: dict) -> dict:
    return next(e for oid, e in document["objects"].items() if oid.startswith("blob:"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: _event(d)["body"].__setitem__("cost", 99),
        lambda d: _blob(d).__setitem__("data", base64.b64encode(b'{"x":1}').decode()),
        lambda d: _blob(d).__setitem__("data", _blob(d)["data"] + "\n"),
        lambda d: d.__setitem__("root", "run:sha256:" + "0" * 64),
        lambda d: d.__setitem__("root", next(o for o in d["objects"] if o.startswith("event:"))),
        lambda d: d["objects"].__setitem__("blob:sha256:" + "1" * 64, _blob(d)),
        lambda d: d["annotations"][0]["body"]["value"].__setitem__("tags", ["forged"]),
        lambda d: d.__setitem__("signatures", [{"scheme": "tine-sig/2"}]),
        lambda d: d.__setitem__("extra", 1),
        lambda d: _event(d).__setitem__("encoding", "raw"),
    ],
    ids=["event", "blob", "b64", "root", "root-type", "orphan", "annotation", "sig", "key", "enc"],
)
def test_a_tampered_envelope_or_root_is_refused(mutate) -> None:
    raw = _tamper(write_v4(_run()), mutate)
    with pytest.raises(ValueError):
        read_v4(raw)
    assert not Run.verify_integrity(json.loads(raw)).ok


def test_a_missing_linked_object_is_refused() -> None:
    def drop(document: dict) -> None:
        del document["objects"][next(o for o in document["objects"] if o.startswith("blob:"))]

    with pytest.raises(ValueError, match="missing linked object|reach"):
        read_v4(_tamper(write_v4(_run()), drop))


@pytest.mark.parametrize("value", [2**53, -(2**60), 10**30])
def test_a_wide_integer_fails_the_v4_write_and_is_never_rounded(value) -> None:
    run = _run()
    run.add_step(StepKind.tool, {"id": value})
    with pytest.raises(ValueError, match=r"2\*\*53-1.*format v4 refuses"):
        write_v4(run)


def test_show_and_verify_load_a_v4_file(tmp_path: Path, monkeypatch, capsys) -> None:
    from opentine.cli import main

    monkeypatch.setenv(FORMAT_ENV, "4")
    path = _run().save(tmp_path / "run.tine")
    assert is_v4_artifact(json.loads(path.read_bytes()))
    main(["show", str(path)])
    assert "v4-run" in capsys.readouterr().out
    main(["verify", str(path)])
    assert "OK" in capsys.readouterr().out
    assert Run.load(path).id == "v4-run"


def test_v4_is_tinez1_wrapped_like_v2(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(FORMAT_ENV, "4")
    monkeypatch.setenv("OPENTINE_COMPRESS", "zlib")
    run = _run()
    run.add_step(StepKind.think, {"pad": "x" * 4096})
    path = run.save(tmp_path / "run.tine")
    raw = path.read_bytes()
    assert _codec.is_wrapped(raw)
    assert _codec.unwrap(raw, limit=1 << 24) == write_v4(run)
    assert Run.load(path).id == run.id and Run.verify_integrity(path).ok


def test_without_the_env_var_writes_are_v4_and_2_or_3_pin_v2(tmp_path: Path, monkeypatch) -> None:
    # 0.26 phase 6: v4 is the default writer; 2 (or 3) is the deprecated legacy one.
    path = _run().save(tmp_path / "v4.tine")
    assert is_v4_artifact(json.loads(path.read_text()))
    for value in ("2", "3"):
        monkeypatch.setenv(FORMAT_ENV, value)
        saved = _run().save(tmp_path / f"v2-{value}.tine")
        assert json.loads(saved.read_text())["format_version"] == 2


def test_migrations_refuse_to_downgrade_v4() -> None:
    with pytest.raises(MigrationError, match="v4"):
        migrate_dict(json.loads(write_v4(_run())))


def _goldens() -> list[Path]:
    found = sorted((FIXTURES / "compat").glob("*/*.tine"))
    return found + sorted(FIXTURES.glob("golden_*.tine"))


@pytest.mark.parametrize("path", _goldens(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_golden_artifact_reads_unchanged_and_upgrades_on_write(path: Path, monkeypatch):
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    plain = Run.load(path).to_dict()
    monkeypatch.setenv(FORMAT_ENV, "4")
    run = Run.load(path)
    if "linear" in path.name:  # 0.1.0 recorded no created_at: the loader stamps now
        plain["created_at"] = run.created_at
    assert run.to_dict() == plain  # the switch changes writes, never reads
    back = read_v4(write_v4(run))
    assert len(back.steps) == len(run.steps) and back.id == run.id
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before  # never rewritten


def test_a_golden_v3_repository_upgrades_on_write(tmp_path: Path) -> None:
    from opentine.repository import Repo

    shutil.copytree(FIXTURES / "compat" / "v0_18_0" / "repo", tmp_path / "repo")
    repo = Repo.open(tmp_path / "repo")
    run = repo.load_run("heads/main")
    document = json.loads(write_v4(run))
    # A plain write records no provenance: only `tine migrate --to v4` does (SPEC 9.9).
    assert "upgraded_from" not in document
    assert "upgraded_from" not in document["objects"][document["root"]]["body"]
    assert len(read_v4(canonical_json(document)).steps) == len(run.steps)
