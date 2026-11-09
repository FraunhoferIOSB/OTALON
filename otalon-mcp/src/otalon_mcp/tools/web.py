"""Web helper functions for MCP tools.

This module encapsulates logic for lightweight web-related operations such as DuckDuckGo search.
It is initialized via tools.__init__.init(), though no external dependencies are required.

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlencode

import requests
from bs4 import BeautifulSoup
from loguru import logger


def init() -> None:
    """Initialize web helpers (no external dependencies required)."""
    logger.debug("tools.web.init: initialized")


def _duckduckgo_search(query: str, max_results: int = 6) -> List[Dict[str, str]]:
    """Perform a simple DuckDuckGo HTML search and return a list of result dicts.

    Parameters
    ----------
    query : str
        Search query string.
    max_results : int
        Maximum number of result items to return (default: 6).

    Returns
    -------
    list[dict]
        Each dict contains: {"title": str, "url": str, "snippet": str}
    """
    url = "https://html.duckduckgo.com/html/?" + urlencode({"q": query})
    headers = {"User-Agent": "Mozilla/5.0 (+otalon-mcp; contact: local)"}
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    results: List[Dict[str, str]] = []
    for res in soup.select("div.result__body"):
        a = res.select_one("a.result__a")
        snippet_el = res.select_one("a.result__snippet") or res.select_one("div.result__snippet")
        if not a:
            continue
        title = a.get_text(" ", strip=True)
        href = a.get("href", "")
        snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
        if title and href:
            results.append({"title": title, "url": href, "snippet": snippet})
        if len(results) >= max_results:
            break
    return results


def web_search_duckduckgo(query: str, max_results: int = 6) -> Dict[str, Any]:
    """Execute a DuckDuckGo search and wrap results in a standard payload."""
    try:
        results = _duckduckgo_search(query=query, max_results=max_results)
        payload: Dict[str, Any] = {"ok": True, "query": query, "results": results}
        logger.info("tools.web.web_search_duckduckgo -> {count} results", count=len(results))
        return payload
    except Exception as exc:
        err = {"ok": False, "error": f"DuckDuckGo search failed: {exc}"}
        logger.error("tools.web.web_search_duckduckgo error: {err}", err=err)
        return err
