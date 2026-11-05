"""VirusTotal source: GET /api/v3/files/{hash}. See design.md, Data sources and Status mapping.

Only ever sends a hash. Never call POST /api/v3/files (that uploads a file).
"""

from typing import Any

import httpx

from backend.config import Settings
from backend.models import SourceResult, source_error
from backend.sources.http import json_body, send, unix_to_iso

NAME = "VirusTotal"
FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{hash}"
GUI_FILE_URL = "https://www.virustotal.com/gui/file/{sha256}"

STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected")


async def lookup(hash_value: str, hash_type: str, client: httpx.AsyncClient, settings: Settings) -> SourceResult:
    if not settings.vt_api_key:
        return source_error("missing_key", "VT_API_KEY is not set in .env")

    response = await send(
        client,
        "GET",
        FILE_REPORT_URL.format(hash=hash_value),
        source=NAME,
        timeout=settings.source_timeout_seconds,
        headers={"x-apikey": settings.vt_api_key, "accept": "application/json"},
    )
    if isinstance(response, SourceResult):
        return response

    status = response.status_code
    if status == 200:
        try:
            return SourceResult(status="ok", data=_normalize(response.json()))
        except (ValueError, KeyError, TypeError):
            return source_error("upstream_error", "VirusTotal returned a response in an unexpected format")
    if status == 404:
        return SourceResult(status="not_found")
    if status == 401:
        return source_error("auth_failed", f"VirusTotal rejected the API key (HTTP 401{_vt_code(response)})")
    if status == 429:
        return source_error(
            "rate_limited",
            f"VirusTotal returned 429 Too Many Requests{_vt_code(response, sep=': ')} (free limit: 4/min, 500/day)",
        )
    return source_error("upstream_error", f"VirusTotal returned HTTP {status}{_vt_code(response)}")


def _normalize(body: dict[str, Any]) -> dict[str, Any]:
    data = body["data"]
    attributes = data["attributes"]
    stats = attributes.get("last_analysis_stats") or {}
    first_submission = attributes.get("first_submission_date")
    sha256 = attributes.get("sha256") or data["id"]
    return {
        **{key: int(stats.get(key, 0)) for key in STAT_KEYS},
        "type_description": attributes.get("type_description"),
        "names": list(attributes.get("names") or []),
        "first_submission_date": unix_to_iso(first_submission) if first_submission is not None else None,
        "link": GUI_FILE_URL.format(sha256=sha256),
    }


def _vt_code(response: httpx.Response, sep: str = ", ") -> str:
    """VirusTotal's error code (e.g. QuotaExceededError), if the body has one."""
    try:
        code = json_body(response)["error"]["code"]
    except (KeyError, TypeError):
        return ""
    return f"{sep}{code}" if isinstance(code, str) else ""
