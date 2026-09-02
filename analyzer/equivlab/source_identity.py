"""Canonical source-identity policy shared by CLI and API analysis."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse


APPROVED_SOURCE_HOST = "raw.githubusercontent.com"
MAX_CANONICAL_SOURCE_BYTES = 100_000
MAX_SOURCE_URL_CHARS = 1_000
COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")


def validate_source_url(url: str) -> str:
    if url != url.strip() or len(url) == 0 or len(url) > MAX_SOURCE_URL_CHARS:
        raise ValueError("Source URL is empty, padded, or too long.")
    if any(ord(character) < 32 for character in url):
        raise ValueError("Source URL contains control characters.")

    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Source URL contains an invalid port.") from exc

    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != APPROVED_SOURCE_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ValueError(
            "Source URL must use the approved raw GitHub HTTPS host without credentials, ports, query, or fragment."
        )
    if "%" in parsed.path or "//" in parsed.path or parsed.path.endswith("/"):
        raise ValueError("Source URL path must use an unencoded canonical file path.")

    encoded_parts = [part for part in parsed.path.split("/") if part]
    decoded_parts = [unquote(part) for part in encoded_parts]
    if (
        len(decoded_parts) < 4
        or COMMIT_SHA_PATTERN.fullmatch(decoded_parts[2]) is None
        or any(part in {".", ".."} or "/" in part or "\\" in part or "\x00" in part for part in decoded_parts)
    ):
        raise ValueError("Source URL must contain an organization, repository, lowercase full commit SHA, and file path.")
    return url
