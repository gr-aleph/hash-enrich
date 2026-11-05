"""Shared helpers for source modules: one request with an overall timeout, and date conversion."""

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.models import SourceResult, source_error


async def send(
    client: httpx.AsyncClient, method: str, url: str, *, source: str, timeout: float, **kwargs: Any
) -> httpx.Response | SourceResult:
    """Send one request. Returns the response, or a SourceResult error for a timeout or connection failure.

    asyncio.timeout caps the whole request; httpx's own timeout only caps each step.
    Error messages never include request details, because those contain the key header.
    """
    try:
        async with asyncio.timeout(timeout):
            return await client.request(method, url, timeout=timeout, **kwargs)
    except (TimeoutError, httpx.TimeoutException):
        return source_error("timeout", f"{source} did not answer within {timeout:g} seconds")
    except httpx.HTTPError as exc:
        return source_error("upstream_error", f"Could not reach {source} ({type(exc).__name__})")


def json_body(response: httpx.Response) -> Any:
    """The parsed JSON body, or None if the body is not JSON."""
    try:
        return response.json()
    except ValueError:
        return None


def unix_to_iso(timestamp: int) -> str:
    return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def abusech_to_iso(value: str | None) -> str | None:
    """abuse.ch dates are UTC, e.g. '2026-04-17 11:47:11' (MalwareBazaar) or '2026-11-05 19:57:10 UTC' (ThreatFox)."""
    if not value:
        return None
    try:
        parsed = datetime.strptime(value.removesuffix(" UTC").strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value  # unknown format: pass it through rather than fail the whole source
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
