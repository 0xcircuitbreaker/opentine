"""Review fixes for 0.45.1 events and webhooks."""

from __future__ import annotations

import ipaddress
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine.remote import _events, _events_http
from opentine.remote._webhook_delivery import Dispatcher
from opentine.remote._webhooks import blocked, resolve


@pytest.mark.parametrize(
    "text",
    ["64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::", "::ffff:10.0.0.1", "169.254.169.254"],
)
def test_embedded_private_ipv4_is_blocked(text):
    assert blocked(ipaddress.ip_address(text))
    infos = [(None, None, None, "", (text, 443))]
    with pytest.raises(ValueError):
        resolve("x.example", 443, False, resolver=lambda *a, **k: infos)


def test_public_addresses_pass():
    assert not blocked(ipaddress.ip_address("8.8.8.8"))


def test_stream_slot_is_released_when_closed_before_iteration():
    hub = _events.EventHub(max_streams=1)
    assert hub.streams.acquire(blocking=False)
    frames = _events_http._stream(hub, "t", 0, False, 0, 1)
    body = _events_http._Released(hub.streams, frames)
    body.close()
    body.close()
    assert hub.streams.acquire(blocking=False)


def test_a_tenant_evicted_and_rewritten_gets_a_reset(monkeypatch):
    monkeypatch.setattr(_events, "MAX_TENANTS", 1)
    hub = _events.EventHub()
    first = hub.publish("a", "run.created", {"runs": [], "total": 0})
    seq, _ = hub.position(first["id"])
    hub.publish("a", "run.created", {"runs": [], "total": 0})
    hub.publish("b", "run.created", {"runs": [], "total": 0})  # evicts "a"
    hub.publish("a", "run.created", {"runs": [], "total": 0})  # "a" again, fresh buffer
    _, lost, _ = hub.after("a", seq)
    assert lost


class _Hooks:
    allow_private = False
    key = Ed25519PrivateKey.generate()

    def list(self, tenant):
        return [{"id": "wh_1", "kinds": ["run.created"], "url": "https://x.example/"}]


def test_dispatcher_thread_survives_an_unexpected_error():
    done = threading.Event()

    def sender(*_args):
        done.set()
        return 204

    dispatcher = Dispatcher(_Hooks(), sender=sender)
    original, failed = dispatcher.deliver, []

    def deliver(job):
        if not failed:
            failed.append(job)
            raise TypeError("boom")
        return original(job)

    dispatcher.deliver = deliver
    event = {"kind": "run.created", "tenant": "t", "id": "e-1"}
    dispatcher(event)
    dispatcher(event)
    assert done.wait(5)
    assert failed
