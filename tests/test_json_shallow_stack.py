"""Deep JSON never overflows the C stack, even in a 512 KiB / 1 MiB thread (Windows)."""

from __future__ import annotations

import threading

import pytest

from opentine._json_shallow import MAX_NESTING, loads, nesting


def _in_thread(size: int, fn):
    old = threading.stack_size(size)
    out: list = []
    try:
        t = threading.Thread(target=lambda: out.append(fn()))
        t.start()
        t.join()
    finally:
        threading.stack_size(old)
    assert out, "the thread died"
    return out[0]


def _try(text: str):
    try:
        return loads(text)
    except ValueError as exc:
        return exc


@pytest.mark.parametrize("size", [512 * 1024, 1024 * 1024])
def test_deepest_allowed_and_over_deep_json_in_a_small_stack(size):
    ok = "[" * MAX_NESTING + "]" * MAX_NESTING
    assert isinstance(_in_thread(size, lambda: _try(ok)), list)
    deep = "[" * 100_000 + "]" * 100_000
    assert isinstance(_in_thread(size, lambda: _try(deep)), ValueError)
    assert isinstance(_in_thread(size, lambda: _try('{"a":' * 100_000)), ValueError)


def test_brackets_inside_strings_do_not_count():
    assert nesting('["[[[[", "\\"{{{"]') == 1
    assert loads('{"k": "[[[[[[[["}') == {"k": "[[[[[[[["}


@pytest.mark.parametrize("size", [512 * 1024, 1024 * 1024])
def test_hook_and_hermes_inputs_survive_a_small_stack(tmp_path, size):
    from opentine import _hook_journal as journal
    from opentine.trace import _import_hermes as hermes

    deep = "[" * 100_000 + "]" * 100_000
    assert _in_thread(size, lambda: journal.parse_payload(deep.encode())) is None
    text = f"<tool_call>{deep}</tool_call><tool_call>{{}}</tool_call>"
    found = _in_thread(size, lambda: hermes._blocks(hermes._CALL, text))
    assert found == ([{}], 1)


@pytest.mark.parametrize("size", [512 * 1024, 1024 * 1024])
def test_policy_json_refuses_deep_nesting_in_a_small_stack(size):
    from opentine._policy import strict_json

    def attempt(text):
        try:
            return strict_json(text)
        except ValueError as exc:
            return exc

    deep = "[" * 100_000 + "]" * 100_000
    assert isinstance(_in_thread(size, lambda: attempt(deep)), ValueError)
    assert _in_thread(size, lambda: attempt('{"k": [[1]]}')) == {"k": [[1]]}


@pytest.mark.parametrize("size", [512 * 1024, 1024 * 1024])
def test_keyless_bundle_reader_refuses_deep_nesting_in_a_small_stack(tmp_path, size):
    import inspect

    from opentine import _cli_keyless

    assert "shallow_loads(Path(args.bundle)" in inspect.getsource(_cli_keyless._verify)
    deep = ("[" * 100_000 + "]" * 100_000).encode()
    assert isinstance(_in_thread(size, lambda: _try(deep.decode())), ValueError)
