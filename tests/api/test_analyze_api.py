from __future__ import annotations

from email.message import Message

import pytest

from api import analyze


PINNED_URL = (
    "https://raw.githubusercontent.com/equivlab/demo/"
    "0123456789abcdef0123456789abcdef01234567/contracts/example.py"
)


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/equivlab/demo/" + "1" * 40 + "/contract.py",
        "https://example.com/equivlab/demo/" + "1" * 40 + "/contract.py",
        "https://raw.githubusercontent.com@127.0.0.1/equivlab/demo/" + "1" * 40 + "/contract.py",
        "https://raw.githubusercontent.com:443/equivlab/demo/" + "1" * 40 + "/contract.py",
        "https://raw.githubusercontent.com/equivlab/demo/main/contract.py",
        "https://raw.githubusercontent.com/equivlab/demo/" + "1" * 40 + "/%2e%2e/secret",
        "https://raw.githubusercontent.com/equivlab/demo/" + "1" * 40 + "/contract.py?raw=1",
    ],
)
def test_source_fetch_allowlist_rejects_unapproved_or_unpinned_urls(url: str) -> None:
    with pytest.raises(ValueError):
        analyze._validate_source_url(url)


def test_source_fetch_allowlist_accepts_a_commit_pinned_raw_github_url() -> None:
    assert analyze._validate_source_url(PINNED_URL) == PINNED_URL


def test_fetch_uses_the_validated_url_and_enforces_the_byte_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, amount: int) -> bytes:
            assert amount == analyze.MAX_SOURCE_BYTES + 1
            return b"contract source\n"

    class Opener:
        def open(self, request, timeout: int):
            assert request.full_url == PINNED_URL
            assert timeout == analyze.FETCH_TIMEOUT_SECONDS
            return Response()

    monkeypatch.setattr(analyze, "_SOURCE_OPENER", Opener())
    assert analyze._fetch_source(PINNED_URL) == b"contract source\n"


def test_request_fields_require_a_json_object_with_string_identity_fields() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        analyze._request_fields([])
    with pytest.raises(ValueError, match="source_url"):
        analyze._request_fields({"source_url": 1, "expected_sha256": "0" * 64})
    with pytest.raises(ValueError, match="expected_sha256"):
        analyze._request_fields({"source_url": PINNED_URL, "expected_sha256": None})
    with pytest.raises(ValueError, match="source must"):
        analyze._request_fields({"source_url": PINNED_URL, "expected_sha256": "0" * 64, "source": {}})


def test_request_fields_preserve_source_url_for_policy_validation() -> None:
    fields = analyze._request_fields({
        "source_url": f" {PINNED_URL} ",
        "expected_sha256": f" {'0' * 64} ",
        "source": "contract source",
    })
    assert fields == (f" {PINNED_URL} ", "0" * 64, "contract source")
