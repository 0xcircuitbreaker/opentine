"""The only network code of the TUF client: one bounded HTTPS GET.

``urllib`` with a timeout, no proxy environment, no redirects and a hard size
limit. A 403/404 is "absent" (``None``), which is how a root chain walk ends
(object stores answer 403 for a missing key). Tests set ``FETCH`` to a callable
``(url, limit) -> bytes | None`` that serves fixture metadata from a dict.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

TIMEOUT_SECONDS = 30.0
#: Test override: ``(url, limit) -> bytes | None``; ``None`` means the network.
FETCH: Any = None

__all__ = ["FETCH", "FetchError", "fetch"]


class FetchError(ValueError):
    """A repository request failed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def fetch(url: str, limit: int) -> bytes | None:
    """GET *url*; ``None`` if absent; ``FetchError`` past *limit* bytes or on failure."""
    if FETCH is not None:
        data = FETCH(url, limit)
    else:
        if not url.startswith("https://"):
            raise FetchError("TUF repositories must be reached over https://")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        request = urllib.request.Request(url, headers={"User-Agent": "opentine-tuf"})
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                data = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404):
                return None
            raise FetchError(f"{url}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise FetchError(f"{url}: {exc}") from None
    if data is not None and len(data) > limit:
        raise FetchError(f"{url}: response exceeds {limit} bytes")
    return data
