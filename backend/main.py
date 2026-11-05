"""FastAPI app for API contract v1. design.md is the contract; if this code disagrees, fix the code."""

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.config import Settings, get_settings
from backend.hashes import INVALID_HASH_MESSAGE, parse_hash
from backend.models import ErrorResponse, HashResponse, SourceResult, source_error
from backend.sources import SOURCES

app = FastAPI(
    title="hash-enrich",
    version="1",
    description="Look up a file hash in several threat-intelligence sources. Contract: design.md.",
)

ANSWERED = ("ok", "not_found")


async def get_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client


def invalid_hash_response() -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": {"code": "invalid_hash", "message": INVALID_HASH_MESSAGE}})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default is 422 with its own body; the contract promises this 400 body.
    return invalid_hash_response()


@app.get("/api/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get(
    "/api/v1/hash/{hash}",
    response_model=HashResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid hash; no source was called"},
        502: {"model": HashResponse, "description": "No source returned ok or not_found"},
    },
)
async def lookup_hash(
    hash: str,
    client: httpx.AsyncClient = Depends(get_client),
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    parsed = parse_hash(hash)
    if parsed is None:
        return invalid_hash_response()
    hash_value, hash_type = parsed

    names = list(SOURCES)
    outcomes = await asyncio.gather(
        *(SOURCES[name](hash_value, hash_type, client, settings) for name in names),
        return_exceptions=True,
    )
    results = {name: _as_result(name, outcome) for name, outcome in zip(names, outcomes)}

    body = HashResponse(
        hash=hash_value,
        hash_type=hash_type,
        queried_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        sources=results,
    )
    answered = any(result.status in ANSWERED for result in results.values())
    return JSONResponse(status_code=200 if answered else 502, content=body.model_dump(mode="json"))


def _as_result(name: str, outcome: SourceResult | BaseException) -> SourceResult:
    """A bug in one source module becomes that source's error, never a crash of the whole response."""
    if isinstance(outcome, SourceResult):
        return outcome
    return source_error("upstream_error", f"Unexpected error in the {name} source ({type(outcome).__name__})")
