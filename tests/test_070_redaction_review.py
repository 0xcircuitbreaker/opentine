"""Red-team rows for publication redaction: inputs that slipped through, and fixes."""

from __future__ import annotations

import json
from collections import Counter

import pytest

from opentine import _redact_publish, _redacted_derive
from opentine._tree import encode_tree, parse_tree
from opentine.kernel import TREE_SCHEMA, ObjectEnvelope

LEAKS = [
    ("\\\\fs01\\Users\\alice\\doc.txt", "<HOME>\\doc.txt"),  # UNC share of a home
    ("\\\\fs01\\home$\\alice\\x", "<HOME>\\x"),
    ("\\\\fs01\\c$\\Users\\alice\\x", "<HOME>\\x"),
    ("\\\\\\\\fs01\\\\Users\\\\alice\\\\x", "<HOME>\\\\x"),  # the same, JSON-escaped
    ("C:\\\\\\\\Users\\\\\\\\alice\\\\\\\\x", "<HOME>\\\\\\\\x"),  # JSON inside JSON
    ("?p=%2Fhome%2Falice%2Fx", "?p=<HOME>%2Fx"),  # URL-encoded
    ("C%3A%5CUsers%5Calice%5Cx", "<HOME>%5Cx"),
    ("/home/alice?raw=1", "<HOME>?raw=1"),
    ("/var/home/alice/x", "<HOME>/x"),  # Fedora Silverblue homes
    ("/mnt/c/Users/alice/x", "<HOME>/x"),  # WSL view of a Windows home
    ("/System/Volumes/Data/Users/alice/x", "<HOME>/x"),
    ("alice%40example.com", "<EMAIL>"),
    ("alice\\u0040example.com", "<EMAIL>"),  # JSON-escaped @
    ("alice\uff20example.com", "<EMAIL>"),  # fullwidth @
    ("https://alice:[REDACTED]@example.com/x", "https://<USER>:[REDACTED]@example.com/x"),
    ("https://alice@example.com/x", "https://<USER>@example.com/x"),
    ("alice@laptop:~$ ls", "<USER>@laptop:~$ ls"),  # a shell prompt names the login
]

KEEP = [
    "https://git@github.com/o/r",
    "/var/homebrew/x",
    "bob@laptop is not the login",
    "src%2Fhome%2Fviews",
    "\\\\fs01\\public\\docs",
    "@app.route('/users/<id>')",
]


@pytest.mark.parametrize(("text", "expected"), LEAKS)
def test_leaks_found_in_review_are_redacted(text, expected):
    assert _redact_publish.scrub_text(text, login="alice")[0] == expected


@pytest.mark.parametrize("text", KEEP)
def test_review_false_positives_are_left_alone(text):
    assert _redact_publish.scrub_text(text, login="alice") == (text, Counter())


def test_json_escaped_unc_paths_stay_valid_json():
    raw = json.dumps({"p": "\\\\fs\\Users\\alice\\x", "e": "alice@example.com"}).encode()
    clean, counts = _redact_publish.scrub_bytes(raw, login=None)
    assert json.loads(clean) == {"p": "<HOME>\\x", "e": "<EMAIL>"}
    assert counts == {"path": 1, "email": 1}


def test_tree_entry_names_are_redacted_and_the_tree_stays_valid():
    blob = ObjectEnvelope.create("blob", b"hi", 1)
    body = encode_tree([
        {"mode": "100644", "name": "from-alice@example.com.eml", "oid": blob.oid},
        {"mode": "100644", "name": "a.txt", "oid": blob.oid},
    ])  # fmt: skip
    counts: Counter[str] = Counter()
    tree = ObjectEnvelope.create("blob", body, TREE_SCHEMA)
    new = _redacted_derive._derived(tree, {}, "alice", counts)
    names = [row["name"] for row in parse_tree(new.body)["entries"]]
    assert names == ["a.txt", "from-<EMAIL>.eml"]
    assert counts == {"email": 1}


def test_identical_derived_objects_are_counted_once():
    seen: dict = {}
    _redacted_derive._count(seen, "blob:x", Counter(path=1))
    _redacted_derive._count(seen, "blob:x", Counter(path=1))
    assert seen == {"blob:x": {"path": 1}}
