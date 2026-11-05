"""Response shapes for API contract v1. design.md is the source of truth."""

from typing import Any, Literal

from pydantic import BaseModel

HashType = Literal["md5", "sha1", "sha256"]
SourceStatus = Literal["ok", "not_found", "unsupported", "error"]
SourceErrorCode = Literal["timeout", "rate_limited", "auth_failed", "upstream_error", "missing_key"]


class SourceError(BaseModel):
    code: SourceErrorCode
    message: str


class SourceResult(BaseModel):
    status: SourceStatus
    data: dict[str, Any] | None = None
    error: SourceError | None = None


def source_error(code: SourceErrorCode, message: str) -> SourceResult:
    return SourceResult(status="error", error=SourceError(code=code, message=message))


class HashResponse(BaseModel):
    hash: str
    hash_type: HashType
    queried_at: str
    sources: dict[str, SourceResult]


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
