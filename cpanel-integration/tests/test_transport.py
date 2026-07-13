from __future__ import annotations

import io
import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from cpanel_admin.errors import TransportError, UAPIError
from cpanel_admin.profiles import Profile
from cpanel_admin.transport import SameOriginRedirectHandler, UAPITransport, Upload


class FakeResponse:
    def __init__(self, payload: object, *, status: int = 200) -> None:
        self.status = status
        self._body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requests: list[tuple[Request, int]] = []

    def open(self, request: Request, timeout: int) -> FakeResponse:
        self.requests.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.fixture
def profile() -> Profile:
    return Profile("production", "cpanel.example.com", 2083, "account", "ciphertext")


def test_success_builds_verified_uapi_request(profile: Profile) -> None:
    opener = FakeOpener(
        FakeResponse(
            {
                "result": {
                    "status": 1,
                    "data": {"main_domain": "example.com"},
                    "warnings": ["notice"],
                    "messages": ["ok"],
                }
            }
        )
    )
    transport = UAPITransport(opener=opener)
    response = transport.call(profile, "secret-token", "DomainInfo", "list_domains", {})
    request, timeout = opener.requests[0]
    assert response.data == {"main_domain": "example.com"}
    assert response.warnings == ["notice"]
    assert response.messages == ["ok"]
    assert request.full_url == "https://cpanel.example.com:2083/execute/DomainInfo/list_domains"
    assert request.get_header("Authorization") == "cpanel account:secret-token"
    assert timeout == 30


def test_parameters_are_url_encoded(profile: Profile) -> None:
    opener = FakeOpener(FakeResponse({"result": {"status": 1, "data": None}}))
    UAPITransport(opener=opener).call(
        profile, "token", "Fileman", "list_files", {"dir": "public html", "show": 1}
    )
    assert opener.requests[0][0].full_url.endswith("?dir=public+html&show=1")


def test_multipart_upload_uses_post_without_query_secrets(profile: Profile) -> None:
    opener = FakeOpener(FakeResponse({"result": {"status": 1, "data": None}}))
    UAPITransport(opener=opener).call(
        profile,
        "token",
        "Fileman",
        "upload_files",
        {"dir": "public_html"},
        method="POST",
        files={"file-1": Upload("site.txt", b"hello", "text/plain")},
    )
    request = opener.requests[0][0]
    assert request.method == "POST"
    assert request.full_url.endswith("/execute/Fileman/upload_files")
    assert request.get_header("Content-type").startswith("multipart/form-data; boundary=")
    assert b'name="dir"' in request.data
    assert b"public_html" in request.data
    assert b'name="file-1"; filename="site.txt"' in request.data
    assert b"hello" in request.data


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (URLError(TimeoutError()), "timed out"),
        (URLError(ssl.SSLError("bad certificate")), "TLS"),
        (URLError(OSError("secret-token connection failed")), "Network request failed"),
    ],
)
def test_transport_failures_are_typed_and_redacted(
    profile: Profile, failure: Exception, message: str
) -> None:
    transport = UAPITransport(opener=FakeOpener(failure))
    with pytest.raises(TransportError, match=message) as error:
        transport.call(profile, "secret-token", "DomainInfo", "list_domains", {})
    assert "secret-token" not in str(error.value)


def test_http_and_uapi_failures_are_typed(profile: Profile) -> None:
    http_error = HTTPError("https://example", 403, "Forbidden", {}, io.BytesIO(b"denied"))
    with pytest.raises(TransportError, match="HTTP 403"):
        UAPITransport(opener=FakeOpener(http_error)).call(
            profile, "token", "DomainInfo", "list_domains", {}
        )
    opener = FakeOpener(FakeResponse({"result": {"status": 0, "errors": ["permission denied"]}}))
    with pytest.raises(UAPIError, match="permission denied"):
        UAPITransport(opener=opener).call(profile, "token", "DomainInfo", "list_domains", {})


@pytest.mark.parametrize("body", [b"not-json", b"[]"])
def test_invalid_response_shapes_are_rejected(profile: Profile, body: bytes) -> None:
    with pytest.raises(TransportError, match="valid JSON object"):
        UAPITransport(opener=FakeOpener(FakeResponse(body))).call(
            profile, "token", "DomainInfo", "list_domains", {}
        )


def test_oversized_response_is_rejected(profile: Profile) -> None:
    body = b"x" * (10 * 1024 * 1024 + 1)
    with pytest.raises(TransportError, match="10 MiB"):
        UAPITransport(opener=FakeOpener(FakeResponse(body))).call(
            profile, "token", "DomainInfo", "list_domains", {}
        )


def test_cross_origin_redirect_is_rejected() -> None:
    handler = SameOriginRedirectHandler()
    request = Request("https://cpanel.example.com:2083/execute/A/B")
    with pytest.raises(TransportError, match="different origin"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://attacker.example/steal",
        )
