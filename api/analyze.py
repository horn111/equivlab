"""Vercel HTTP boundary for the deterministic EquivLab analyzer."""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


from equivlab.report import analyze_source


MAX_SOURCE_BYTES = 512_000
FETCH_TIMEOUT_SECONDS = 12
APPROVED_SOURCE_HOST = "raw.githubusercontent.com"
COMMIT_SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_SOURCE_OPENER = build_opener(_RejectRedirects)


def _validate_source_url(url: str) -> str:
    if url != url.strip() or len(url) == 0 or len(url) > 1_000:
        raise ValueError("Source URL is empty, padded, or too long.")

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
        raise ValueError("Source URL must use the approved raw GitHub HTTPS host without credentials, ports, query, or fragment.")

    encoded_parts = [part for part in parsed.path.split("/") if part]
    decoded_parts = [unquote(part) for part in encoded_parts]
    if (
        len(decoded_parts) < 4
        or COMMIT_SHA_PATTERN.fullmatch(decoded_parts[2]) is None
        or any(part in {".", ".."} or "/" in part or "\\" in part or "\x00" in part for part in decoded_parts)
    ):
        raise ValueError("Source URL must contain an organization, repository, full commit SHA, and file path.")
    return url


def _fetch_source(url: str) -> bytes:
    validated_url = _validate_source_url(url)
    request = Request(validated_url, headers={"User-Agent": "EquivLab/0.1 source-inspector"})
    with _SOURCE_OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_SOURCE_BYTES:
            raise ValueError("Source exceeds the 512 KB analysis limit.")
        source = response.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("Source exceeds the 512 KB analysis limit.")
    return source


def _request_fields(payload: object) -> tuple[str, str, str | None]:
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    source_url = payload.get("source_url")
    expected_sha256 = payload.get("expected_sha256")
    supplied_source = payload.get("source")
    if not isinstance(source_url, str):
        raise ValueError("source_url must be a string.")
    if not isinstance(expected_sha256, str):
        raise ValueError("expected_sha256 must be a string.")
    if supplied_source is not None and not isinstance(supplied_source, str):
        raise ValueError("source must be UTF-8 text.")
    return source_url, expected_sha256.strip(), supplied_source


class handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Allow", "POST, OPTIONS")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_SOURCE_BYTES * 2:
                self._send(400, {"error": "Request body is empty or too large."})
                return
            payload = json.loads(self.rfile.read(length))
            source_url, expected_sha256, supplied_source = _request_fields(payload)

            if supplied_source is None:
                if not source_url:
                    self._send(400, {"error": "source_url is required when source text is not supplied."})
                    return
                source: bytes | str = _fetch_source(source_url)
                source_mode = "retrieved"
            else:
                if len(supplied_source.encode("utf-8")) > MAX_SOURCE_BYTES:
                    raise ValueError("Source exceeds the 512 KB analysis limit.")
                source = supplied_source
                source_mode = "submitted"

            report = analyze_source(source, source_url, expected_sha256)
            self._send(200, {"report": report, "source_mode": source_mode})
        except (HTTPError, URLError, TimeoutError) as exc:
            self._send(502, {"error": f"Pinned source could not be retrieved: {exc}"})
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception:
            self._send(500, {"error": "Analysis failed at the service boundary."})


if __name__ == "__main__":
    print("EquivLab analyzer API listening on http://127.0.0.1:8765")
    HTTPServer(("127.0.0.1", 8765), handler).serve_forever()
