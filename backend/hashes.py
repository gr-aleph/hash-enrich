"""Hash validation and type detection. See design.md, API contract."""

import re

_HEX = re.compile(r"[0-9a-fA-F]+")
_TYPE_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}

INVALID_HASH_MESSAGE = "Expected 32, 40 or 64 hex characters (MD5, SHA-1, SHA-256)"


def parse_hash(value: str) -> tuple[str, str] | None:
    """Return (lowercased hash, hash type), or None if the value is not a valid hash.

    Strict on purpose: surrounding spaces are invalid here. The frontend trims them.
    """
    hash_type = _TYPE_BY_LENGTH.get(len(value))
    if hash_type is None or not _HEX.fullmatch(value):
        return None
    return value.lower(), hash_type
