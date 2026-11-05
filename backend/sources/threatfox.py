"""ThreatFox source: POST search_ioc with exact_match. See design.md, Data sources and Status mapping.

search_ioc finds the hash itself as an IOC (ThreatFox stores md5_hash, sha1_hash and sha256_hash IOCs).
search_hash is not used: it returns IOCs *linked to* a sample, such as its C2 URLs.

Recorded answers (tests/fixtures/threatfox/): found = HTTP 200 "ok"; unknown = HTTP 200 "no_result";
bad key = HTTP 403 "unknown_auth_key". IOCs older than 6 months expire and are not returned.
"""

from typing import Any

import httpx

from backend.config import Settings
from backend.models import SourceResult, source_error
from backend.sources.http import abusech_to_iso, json_body, send

NAME = "ThreatFox"
API_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def lookup(hash_value: str, hash_type: str, client: httpx.AsyncClient, settings: Settings) -> SourceResult:
    if not settings.abusech_auth_key:
        return source_error("missing_key", "ABUSECH_AUTH_KEY is not set in .env")

    response = await send(
        client,
        "POST",
        API_URL,
        source=NAME,
        timeout=settings.source_timeout_seconds,
        json={"query": "search_ioc", "search_term": hash_value, "exact_match": True},
        headers={"Auth-Key": settings.abusech_auth_key},
    )
    if isinstance(response, SourceResult):
        return response

    body = json_body(response)
    query_status = body.get("query_status") if isinstance(body, dict) else None

    if response.status_code in (401, 403) or query_status == "unknown_auth_key":
        return source_error("auth_failed", f"ThreatFox rejected the abuse.ch key (HTTP {response.status_code})")
    if response.status_code == 429:
        return source_error("rate_limited", "ThreatFox returned 429 Too Many Requests")
    if response.status_code != 200:
        return source_error("upstream_error", f"ThreatFox returned HTTP {response.status_code}")
    if query_status == "no_result":
        return SourceResult(status="not_found")
    if query_status == "ok" and isinstance(body.get("data"), list) and body["data"]:
        try:
            return SourceResult(status="ok", data={"matches": [_normalize(ioc) for ioc in body["data"]]})
        except (AttributeError, TypeError):
            pass
        return source_error("upstream_error", "ThreatFox returned a response in an unexpected format")
    if query_status == "ok":
        return source_error("upstream_error", "ThreatFox returned a response in an unexpected format")
    return source_error("upstream_error", f"ThreatFox returned query_status {query_status!r}")


def _normalize(ioc: dict[str, Any]) -> dict[str, Any]:
    return {
        "malware_printable": ioc.get("malware_printable"),
        "threat_type": ioc.get("threat_type"),
        "confidence_level": ioc.get("confidence_level"),
        "first_seen": abusech_to_iso(ioc.get("first_seen")),
        "last_seen": abusech_to_iso(ioc.get("last_seen")),
        # Optional details (added within v1).
        "malware_alias": ioc.get("malware_alias"),
        "tags": list(ioc.get("tags") or []),
        "malpedia": ioc.get("malware_malpedia"),
        "reference": ioc.get("reference"),
    }
