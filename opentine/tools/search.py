"""Pluggable web search — Tavily, Exa, Brave via env, DuckDuckGo HTML fallback."""

from __future__ import annotations

import os
import re

import httpx


async def search(query: str, max_results: int = 5) -> str:
    """Search the web. Auto-selects provider from env vars, falls back to DuckDuckGo."""
    if os.environ.get("TAVILY_API_KEY"):
        return await _tavily(query, max_results)
    if os.environ.get("EXA_API_KEY"):
        return await _exa(query, max_results)
    if os.environ.get("BRAVE_API_KEY"):
        return await _brave(query, max_results)
    return await _duckduckgo(query, max_results)


async def _tavily(query: str, max_results: int) -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            "https://api.tavily.com/search",
            json={
                "api_key": os.environ["TAVILY_API_KEY"],
                "query": query,
                "max_results": max_results,
            },
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    return "\n\n".join(f"[{r['title']}]({r['url']})\n{r.get('content', '')[:300]}" for r in results)


async def _exa(query: str, max_results: int) -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            "https://api.exa.ai/search",
            json={
                "query": query,
                "num_results": max_results,
                "type": "neural",
            },
            headers={"x-api-key": os.environ["EXA_API_KEY"]},
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    return "\n\n".join(f"[{r.get('title', '')}]({r['url']})" for r in results)


async def _brave(query: str, max_results: int) -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={
                "q": query,
                "count": max_results,
            },
            headers={"X-Subscription-Token": os.environ["BRAVE_API_KEY"]},
        )
        resp.raise_for_status()
        results = resp.json().get("web", {}).get("results", [])
    return "\n\n".join(
        f"[{r['title']}]({r['url']})\n{r.get('description', '')[:300]}" for r in results
    )


async def _duckduckgo(query: str, max_results: int) -> str:
    """Fallback: scrape DuckDuckGo HTML lite."""
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        resp = await client.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "opentine/0.1"},
        )
        resp.raise_for_status()
    # Extract result snippets from HTML
    links = re.findall(r'class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>', resp.text)
    snippets = re.findall(
        r'class="result__snippet"[^>]*>(.*?)</(?:td|div|span)>', resp.text, re.DOTALL
    )
    results = []
    for i, (url, title) in enumerate(links[:max_results]):
        title = re.sub(r"<[^>]+>", "", title).strip()
        snippet = re.sub(r"<[^>]+>", "", snippets[i]).strip() if i < len(snippets) else ""
        results.append(f"[{title}]({url})\n{snippet[:200]}")
    return "\n\n".join(results) if results else f"No results found for: {query}"
