"""Linear, bounded visible-text extraction for untrusted HTML."""

from __future__ import annotations

from html.parser import HTMLParser

MAX_SEARCH_RESULTS = 100
_MAX_SEARCH_FIELD = 2_048
_MAX_SEARCH_URL = 4_096


class _VisibleText(HTMLParser):
    def __init__(self, limit: int, max_raw: int):
        super().__init__(convert_charrefs=True)
        self.limit = limit
        # Separate budget for retained source. The output budget must not be spent
        # on markup, but retention still needs a ceiling; this one is proportional
        # to the input the caller already accepted.
        self.max_raw = max_raw
        self.hidden = 0
        self.parts: list[str] = []
        self.length = 0
        self.raw = 0

    def _append(self, value: str) -> None:
        if self.hidden or self.length >= self.limit or self.raw >= self.max_raw:
            return
        # Charge only collapsed, meaningful characters. Counting raw length made the
        # separator emitted for every tag — and the source indentation between them —
        # consume the output budget, so a page whose article follows a long nav list
        # returned nav link text and none of the article, with no truncation marker.
        collapsed = len(" ".join(value.split()))
        self.raw += len(value)
        if not collapsed:
            self.parts.append(" ")
            return
        self.parts.append(value)
        self.length += collapsed + 1

    def handle_starttag(self, tag: str, attrs) -> None:
        del attrs
        if tag.casefold() in {"script", "style"}:
            self.hidden += 1
        else:
            self._append(" ")

    def handle_startendtag(self, tag: str, attrs) -> None:
        del tag, attrs
        self._append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style"} and self.hidden:
            self.hidden -= 1
        else:
            self._append(" ")

    def handle_data(self, data: str) -> None:
        self._append(data)


def visible_text(value: str, limit: int) -> str:
    """Extract visible text in linear time, retaining at most ``limit`` characters."""
    if limit < 1:
        raise ValueError("text output limit must be positive")
    parser = _VisibleText(limit, max_raw=len(value) + 1)
    parser.feed(value)
    parser.close()
    return " ".join("".join(parser.parts).split())[:limit]


class _DuckDuckGoResults(HTMLParser):
    """Collect DuckDuckGo result fields without backtracking over HTML."""

    def __init__(self, limit: int):
        super().__init__(convert_charrefs=True)
        self.limit = min(max(limit, 0), MAX_SEARCH_RESULTS)
        self.links: list[tuple[str, str]] = []
        self.snippets: list[str] = []
        self._kind = ""
        self._root = ""
        self._depth = 0
        self._url = ""
        self._parts: list[str] = []
        self._length = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.casefold()
        if self._kind:
            if tag == self._root:
                self._depth += 1
            return
        values = {str(key).casefold(): value or "" for key, value in attrs}
        classes = values.get("class", "").split()
        if tag == "a" and "result__a" in classes and len(self.links) < self.limit:
            self._start("title", tag, values.get("href", "")[:_MAX_SEARCH_URL])
        elif "result__snippet" in classes and len(self.snippets) < self.limit:
            self._start("snippet", tag)

    def handle_startendtag(self, tag: str, attrs) -> None:
        if self._kind:
            return
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self._kind or tag.casefold() != self._root:
            return
        self._depth -= 1
        if self._depth:
            return
        value = " ".join("".join(self._parts).split())
        if self._kind == "title":
            self.links.append((self._url, value))
        else:
            self.snippets.append(value)
        self._kind = ""

    def handle_data(self, data: str) -> None:
        if not self._kind or self._length >= _MAX_SEARCH_FIELD:
            return
        data = data[: _MAX_SEARCH_FIELD - self._length]
        self._parts.append(data)
        self._length += len(data)

    def _start(self, kind: str, root: str, url: str = "") -> None:
        self._kind = kind
        self._root = root
        self._depth = 1
        self._url = url
        self._parts = []
        self._length = 0


def duckduckgo_results(value: str, limit: int) -> list[tuple[str, str, str]]:
    """Parse bounded DuckDuckGo HTML results in one forward pass."""
    if not isinstance(limit, int):
        raise TypeError("search result limit must be an integer")
    parser = _DuckDuckGoResults(limit)
    parser.feed(value)
    parser.close()
    return [
        (url, title, parser.snippets[index] if index < len(parser.snippets) else "")
        for index, (url, title) in enumerate(parser.links)
    ]
