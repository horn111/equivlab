"""Canonical source decoding and hashing."""

from __future__ import annotations

import hashlib


class SourceDecodeError(ValueError):
    """Raised when source bytes cannot be decoded as UTF-8."""


def canonicalize_source(source: bytes | str) -> bytes:
    """Return canonical UTF-8 bytes without changing Python indentation.

    The v1 transform strips a UTF-8 BOM, normalizes CRLF/CR to LF, and adds a
    final LF when absent. Existing final blank lines remain significant.
    """

    if isinstance(source, bytes):
        try:
            text = source.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SourceDecodeError("source is not valid UTF-8") from exc
    elif isinstance(source, str):
        text = source.removeprefix("\ufeff")
    else:
        raise TypeError("source must be bytes or str")

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n"):
        text += "\n"
    return text.encode("utf-8")


def canonical_sha256(source: bytes | str) -> str:
    return hashlib.sha256(canonicalize_source(source)).hexdigest()
