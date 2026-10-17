"""0.10 final pass 3: a bounded form value must never cut a secret in half.

Form values are bounded runs (``{1,512}``, ``{1,4096}``) and used to run before the
vendor token shapes, so a value whose bound fell inside a token removed the token's
prefix (``ghp_``, ``sk-``, ``scheme://user:``) and wrote the rest out after the
``[REDACTED]`` label -- a redaction that looked complete and held almost the whole
secret. Tokens now go first, and every bounded value extends over its own run.
Every value here is fake.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine.redaction import redact_blob, redact_text

#: (value start, the bound of the value that follows it)
FORMS = [
    ("dbg cookie: ", 4096),
    ("log Authorization: ", 4096),
    ("MYSQL_PWD=", 512),
    ("export LDAP_BIND_PW=", 512),
    ("run --db-pwd ", 512),
    ("curl -u admin:", 512),
    ("mysql -u root -p", 512),
    ("redis-cli -h h -a ", 512),
    ("docker login -u me -p ", 512),
    ("machine h login u password ", 512),
]
#: (token, a needle from its tail that must never survive)
TOKENS = [
    ("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd", "QRSTUVWXYZ0123456789abcd"),
    ("ghp_Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8c", "R5qP4oN3mL2kJ1iH0gF9eD8c"),
    ("AKIAQ7FAKEFAKE7FAKEZ", "FAKEFAKE7FAKEZ"),
    ("https://deploy:Sup3rS3cretPassw0rd99zz@db.example.com", "S3cretPassw0rd99zz"),
    ("?access_token=Zq9AccessTokenValue1234567xyz", "AccessTokenValue1234567xyz"),
]


def _line(start: str, bound: int, offset: int, token: str) -> str:
    # The bound falls `offset` bytes into the token.
    return start + "a" * (bound - offset - 1) + "/" + token + " end"


@pytest.mark.parametrize(("start", "bound"), FORMS)
@pytest.mark.parametrize(("token", "needle"), TOKENS)
def test_a_bound_falling_inside_a_token_never_leaves_its_tail(start, bound, token, needle):
    for offset in range(1, 31):
        line = _line(start, bound, offset, token)
        assert needle not in redact_text(line), (start, offset)
        document = json.dumps({"tool_output": line})
        redacted = redact_text(document)
        assert needle not in redacted, (start, offset)
        json.loads(redacted)


@pytest.mark.parametrize(("start", "bound"), FORMS)
def test_a_value_longer_than_its_bound_is_removed_whole(start, bound):
    line = start + "x" * (bound + 40) + "TAILSECRETVALUE"
    assert "TAILSECRETVALUE" not in redact_text(line)
    redacted = redact_text(json.dumps({"tool_output": line}))
    assert "TAILSECRETVALUE" not in redacted
    json.loads(redacted)


@pytest.mark.parametrize(
    "line",
    [
        'MYSQL_PWD=\\"' + "x" * 560 + "TAILSECRETVALUE more",
        "MYSQL_PWD='" + "x" * 560 + "TAILSECRETVALUE more",
        'machine h login u password \\"' + "x" * 560 + "TAILSECRETVALUE more",
    ],
)
def test_an_unclosed_quoted_value_longer_than_its_bound_is_removed_whole(line):
    assert "TAILSECRETVALUE" not in redact_text(line)


def test_a_bare_netrc_value_that_ends_before_a_closer_keeps_the_closer():
    # Only a value that used its whole bound is extended: a short one stops before
    # JSON structure as before.
    assert redact_text("login u password s3cr3t}") == "login u password [REDACTED]}"


def test_extending_a_value_stays_linear():
    def elapsed(size: int) -> float:
        blob = ("MYSQL_PWD=" + "x" * size + " ").encode() * 20
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            redact_blob(blob)
            best = min(best, time.monotonic() - started)
        return best

    small, large = elapsed(5_000), elapsed(20_000)
    assert large < max(small, 0.01) * 8
