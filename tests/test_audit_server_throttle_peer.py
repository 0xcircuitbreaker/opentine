"""Auth throttles key IPv6 clients by /64, like the connection-slot limiter."""

from opentine.remote._auth_throttle import AuthThrottle


def _throttle():
    return AuthThrottle(free_failures=5, base_delay=10.0, clock=lambda: 0.0)


def test_rotating_addresses_within_one_ipv6_64_is_still_throttled():
    throttle = _throttle()
    for i in range(6):
        throttle.failed(f"2001:db8:1:2::{i + 1:x}")
    assert throttle.retry_after("2001:db8:1:2::ffff") > 0
    assert throttle.retry_after("2001:db8:1:3::1") == 0


def test_ipv4_mapped_addresses_share_the_ipv4_record():
    throttle = _throttle()
    for _ in range(6):
        throttle.failed("::ffff:192.0.2.7")
    assert throttle.retry_after("192.0.2.7") > 0
    throttle.succeeded("192.0.2.7")
    assert throttle.retry_after("::ffff:192.0.2.7") == 0


def test_flooding_one_64_cannot_evict_another_clients_lockout():
    throttle = AuthThrottle(free_failures=0, base_delay=10.0, max_clients=4, clock=lambda: 0.0)
    throttle.failed("198.51.100.9")
    for i in range(50):
        throttle.failed(f"2001:db8:9:9::{i + 1:x}")
    assert throttle.retry_after("198.51.100.9") > 0
