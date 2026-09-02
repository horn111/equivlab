"""Vercel HTTP boundary for the deterministic EquivLab analyzer."""

from __future__ import annotations

import json
import threading
import time
import uuid
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


from equivlab.report import analyze_source
from equivlab.source_identity import MAX_CANONICAL_SOURCE_BYTES, validate_source_url


MAX_SOURCE_BYTES = MAX_CANONICAL_SOURCE_BYTES
FETCH_TIMEOUT_SECONDS = 12
RATE_LIMIT_REQUESTS = 24
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_CLIENT_CAPACITY = 2_048
REPORT_CACHE_CAPACITY = 128
REPORT_CACHE_TTL_SECONDS = 900


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_SOURCE_OPENER = build_opener(_RejectRedirects)
_STATE_LOCK = threading.Lock()
_RATE_WINDOWS: OrderedDict[str, deque[float]] = OrderedDict()
_REPORT_CACHE: OrderedDict[tuple[str, str], tuple[float, dict[str, object]]] = OrderedDict()


def _client_key(headers: object, client_address: object) -> str:
    get = getattr(headers, "get", None)
    forwarded = get("x-vercel-forwarded-for") if callable(get) else None
    if not forwarded and callable(get):
        forwarded = get("x-forwarded-for")
    if isinstance(forwarded, str) and forwarded.strip():
        return forwarded.split(",", 1)[0].strip()
    if isinstance(client_address, tuple) and client_address and isinstance(client_address[0], str):
        return client_address[0]
    return "unknown"


def _rate_limit(client_key: str, now: float | None = None) -> int | None:
    """Return retry-after seconds when the bounded per-client window is full."""

    current = time.monotonic() if now is None else now
    cutoff = current - RATE_LIMIT_WINDOW_SECONDS
    with _STATE_LOCK:
        window = _RATE_WINDOWS.pop(client_key, deque())
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= RATE_LIMIT_REQUESTS:
            _RATE_WINDOWS[client_key] = window
            return max(1, int(RATE_LIMIT_WINDOW_SECONDS - (current - window[0])) + 1)
        window.append(current)
        _RATE_WINDOWS[client_key] = window
        while len(_RATE_WINDOWS) > RATE_LIMIT_CLIENT_CAPACITY:
            _RATE_WINDOWS.popitem(last=False)
    return None


def _cache_get(key: tuple[str, str], now: float | None = None) -> dict[str, object] | None:
    current = time.monotonic() if now is None else now
    with _STATE_LOCK:
        cached = _REPORT_CACHE.pop(key, None)
        if cached is None:
            return None
        created_at, payload = cached
        if current - created_at > REPORT_CACHE_TTL_SECONDS:
            return None
        _REPORT_CACHE[key] = (created_at, payload)
        return payload


def _cache_put(key: tuple[str, str], payload: dict[str, object], now: float | None = None) -> None:
    current = time.monotonic() if now is None else now
    with _STATE_LOCK:
        _REPORT_CACHE.pop(key, None)
        _REPORT_CACHE[key] = (current, payload)
        while len(_REPORT_CACHE) > REPORT_CACHE_CAPACITY:
            _REPORT_CACHE.popitem(last=False)


def _validate_source_url(url: str) -> str:
    return validate_source_url(url)


def _fetch_source(url: str) -> bytes:
    validated_url = _validate_source_url(url)
    request = Request(validated_url, headers={"User-Agent": "EquivLab/0.1 source-inspector"})
    with _SOURCE_OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_SOURCE_BYTES:
            raise ValueError("Source exceeds the 100 KB policy limit.")
        source = response.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("Source exceeds the 100 KB policy limit.")
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
    def _send(
        self,
        status: int,
        payload: dict[str, object],
        *,
        request_id: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", request_id)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log_result(self, request_id: str, status: int, started_at: float, **fields: object) -> None:
        event = {
            "duration_ms": round((time.monotonic() - started_at) * 1000),
            "event": "equivlab.analyze",
            "request_id": request_id,
            "status_code": status,
            **fields,
        }
        print(json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True), flush=True)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Allow", "POST, OPTIONS")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        request_id = uuid.uuid4().hex[:16]
        started_at = time.monotonic()
        try:
            retry_after = _rate_limit(_client_key(self.headers, getattr(self, "client_address", None)))
            if retry_after is not None:
                self._send(
                    429,
                    {"error": "Analysis rate limit exceeded. Retry after the indicated interval.", "request_id": request_id},
                    request_id=request_id,
                    extra_headers={"Retry-After": str(retry_after)},
                )
                self._log_result(request_id, 429, started_at, outcome="rate_limited")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_SOURCE_BYTES * 2:
                self._send(400, {"error": "Request body is empty or too large.", "request_id": request_id}, request_id=request_id)
                self._log_result(request_id, 400, started_at, outcome="invalid_body")
                return
            payload = json.loads(self.rfile.read(length))
            source_url, expected_sha256, supplied_source = _request_fields(payload)
            if not source_url:
                self._send(
                    400,
                    {"error": "source_url is required for every analysis mode.", "request_id": request_id},
                    request_id=request_id,
                )
                self._log_result(request_id, 400, started_at, outcome="missing_source_url")
                return
            validated_url = _validate_source_url(source_url)

            if supplied_source is None:
                cache_key = (validated_url, expected_sha256.lower().removeprefix("sha256:"))
                cached = _cache_get(cache_key)
                if cached is not None:
                    self._send(200, cached, request_id=request_id, extra_headers={"X-EquivLab-Cache": "HIT"})
                    self._log_result(request_id, 200, started_at, outcome="ok", source_mode="retrieved", cache="hit")
                    return
                source: bytes | str = _fetch_source(validated_url)
                source_mode = "retrieved"
            else:
                if len(supplied_source.encode("utf-8")) > MAX_SOURCE_BYTES:
                    raise ValueError("Source exceeds the 100 KB policy limit.")
                source = supplied_source
                source_mode = "submitted"

            report = analyze_source(source, validated_url, expected_sha256, source_mode=source_mode)
            response_payload: dict[str, object] = {"report": report, "source_mode": source_mode}
            if supplied_source is None:
                _cache_put(cache_key, response_payload)
            self._send(
                200,
                response_payload,
                request_id=request_id,
                extra_headers={"X-EquivLab-Cache": "MISS" if supplied_source is None else "BYPASS"},
            )
            self._log_result(
                request_id,
                200,
                started_at,
                outcome="ok",
                source_mode=source_mode,
                report_status=report.get("status"),
            )
        except (HTTPError, URLError, TimeoutError) as exc:
            self._send(
                502,
                {"error": "Pinned source could not be retrieved.", "request_id": request_id},
                request_id=request_id,
            )
            self._log_result(request_id, 502, started_at, outcome="fetch_failed", error_type=type(exc).__name__)
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc), "request_id": request_id}, request_id=request_id)
            self._log_result(request_id, 400, started_at, outcome="invalid_request", error_type=type(exc).__name__)
        except Exception as exc:
            self._send(
                500,
                {"error": "Analysis failed at the service boundary.", "request_id": request_id},
                request_id=request_id,
            )
            self._log_result(request_id, 500, started_at, outcome="internal_error", error_type=type(exc).__name__)


if __name__ == "__main__":
    print("EquivLab analyzer API listening on http://127.0.0.1:8765")
    HTTPServer(("127.0.0.1", 8765), handler).serve_forever()
