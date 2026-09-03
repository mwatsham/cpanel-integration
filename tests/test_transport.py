from __future__ import annotations

import io
import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from cpanel_admin.errors import PartialFailure, TransportError, UAPIError, UsageError
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


def test_success_builds_verified_cpanel_api2_request(profile: Profile) -> None:
    opener = FakeOpener(
        FakeResponse(
            {
                "cpanelresult": {
                    "apiversion": 2,
                    "module": "Fileman",
                    "func": "fileop",
                    "event": {"result": 1},
                    "data": [{"src": "public_html/index.php", "result": 1}],
                }
            }
        )
    )
    transport = UAPITransport(opener=opener)

    response = transport.call_api2(
        profile,
        "secret-token",
        "Fileman",
        "fileop",
        {"op": "chmod", "sourcefiles": "public_html/index.php", "metadata": "0644"},
    )

    request, timeout = opener.requests[0]
    assert response.data == [{"src": "public_html/index.php", "result": 1}]
    assert request.full_url.startswith("https://cpanel.example.com:2083/json-api/cpanel?")
    assert "cpanel_jsonapi_apiversion=2" in request.full_url
    assert "cpanel_jsonapi_module=Fileman" in request.full_url
    assert "cpanel_jsonapi_func=fileop" in request.full_url
    assert request.get_header("Authorization") == "cpanel account:secret-token"
    assert timeout == 30


def test_api2_event_failure_is_typed_and_redacted(profile: Profile) -> None:
    opener = FakeOpener(
        FakeResponse(
            {
                "cpanelresult": {
                    "event": {
                        "result": 0,
                        "reason": "chmod failed for token-secret",
                    }
                }
            }
        )
    )

    with pytest.raises(UAPIError) as error:
        UAPITransport(opener=opener).call_api2(
            profile,
            "token",
            "Fileman",
            "fileop",
            {"op": "chmod", "sourcefiles": "public_html/index.php", "metadata": "0644"},
            redaction_secrets=("token-secret",),
        )

    assert "token-secret" not in str(error.value)


def test_api2_item_failure_reports_partial_failure(profile: Profile) -> None:
    opener = FakeOpener(
        FakeResponse(
            {
                "cpanelresult": {
                    "event": {"result": 1},
                    "data": [
                        {"result": 1, "file": "ok.html"},
                        {"result": 0, "file": "bad.html", "message": "permission denied"},
                    ],
                }
            }
        )
    )

    with pytest.raises(PartialFailure, match="item 1: permission denied"):
        UAPITransport(opener=opener).call_api2(
            profile,
            "token",
            "Fileman",
            "fileop",
            {"op": "trash", "sourcefiles": "public_html/bad.html"},
        )


def test_api2_malformed_response_is_rejected(profile: Profile) -> None:
    opener = FakeOpener(FakeResponse({"result": {"status": 1}}))

    with pytest.raises(TransportError, match="invalid API 2 result"):
        UAPITransport(opener=opener).call_api2(
            profile,
            "token",
            "Fileman",
            "fileop",
            {"op": "trash", "sourcefiles": "public_html/bad.html"},
        )


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (URLError(TimeoutError()), "timed out"),
        (URLError(ssl.SSLError("bad certificate")), "TLS"),
        (URLError(OSError("api2-token connection failed")), "Network request failed"),
    ],
)
def test_api2_transport_failures_are_typed_and_redacted(
    profile: Profile, failure: Exception, message: str
) -> None:
    with pytest.raises(TransportError, match=message) as error:
        UAPITransport(opener=FakeOpener(failure)).call_api2(
            profile,
            "api2-token",
            "Fileman",
            "fileop",
            {"op": "trash", "sourcefiles": "public_html/bad.html"},
        )
    assert "api2-token" not in str(error.value)


@pytest.mark.parametrize(
    ("module", "function", "timeout", "message"),
    [
        ("Fileman/bad", "fileop", 30, "Invalid cPanel API 2 operation identifier"),
        ("Fileman", "bad-func", 30, "Invalid cPanel API 2 operation identifier"),
        ("Fileman", "fileop", 0, "Timeout must be between 1 and 120 seconds"),
    ],
)
def test_api2_rejects_invalid_identifiers_and_timeouts(
    profile: Profile, module: str, function: str, timeout: int, message: str
) -> None:
    with pytest.raises(UsageError, match=message):
        UAPITransport(opener=FakeOpener(FakeResponse({}))).call_api2(
            profile,
            "token",
            module,
            function,
            {},
            timeout,
        )


def test_parameters_are_url_encoded(profile: Profile) -> None:
    opener = FakeOpener(FakeResponse({"result": {"status": 1, "data": None}}))
    UAPITransport(opener=opener).call(
        profile, "token", "Fileman", "list_files", {"dir": "public html", "show": 1}
    )
    assert opener.requests[0][0].full_url.endswith("?dir=public+html&show=1")


def test_secret_bearing_get_is_promoted_to_post_form(profile: Profile) -> None:
    opener = FakeOpener(FakeResponse({"result": {"status": 1, "data": None}}))
    UAPITransport(opener=opener).call(
        profile,
        "token",
        "Email",
        "add_pop",
        {"email": "user", "password": "secret"},
        sensitive_names=("password",),
    )
    request = opener.requests[0][0]
    assert request.method == "POST"
    assert "secret" not in request.full_url
    assert request.data == b"email=user&password=secret"


def test_sequence_values_use_repeated_form_keys(profile: Profile) -> None:
    opener = FakeOpener(FakeResponse({"result": {"status": 1, "data": None}}))
    UAPITransport(opener=opener).call(
        profile,
        "token",
        "DNS",
        "mass_edit_zone",
        {"add": ["one", "two"]},
        method="POST",
    )
    assert opener.requests[0][0].data == b"add=one&add=two"


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


@pytest.mark.parametrize(
    "failure",
    [
        URLError(OSError("clone failed for https://github.com/example/private-site.git")),
        OSError("clone failed for https://github.com/example/private-site.git"),
    ],
)
def test_network_failures_redact_explicit_resolved_secrets(
    profile: Profile, failure: Exception
) -> None:
    repository_url = "https://github.com/example/private-site.git"
    transport = UAPITransport(opener=FakeOpener(failure))

    with pytest.raises(TransportError) as error:
        transport.call(
            profile,
            "token",
            "VersionControl",
            "create",
            {"source_repository": f'{{"url":"{repository_url}"}}'},
            redaction_secrets=(repository_url,),
        )

    assert repository_url not in str(error.value)


def test_http_and_uapi_failures_are_typed(profile: Profile) -> None:
    http_error = HTTPError("https://example", 403, "Forbidden", {}, io.BytesIO(b"denied"))
    with pytest.raises(TransportError, match="HTTP 403"):
        UAPITransport(opener=FakeOpener(http_error)).call(
            profile, "token", "DomainInfo", "list_domains", {}
        )
    opener = FakeOpener(FakeResponse({"result": {"status": 0, "errors": ["permission denied"]}}))
    with pytest.raises(UAPIError, match="permission denied"):
        UAPITransport(opener=opener).call(profile, "token", "DomainInfo", "list_domains", {})


def test_uapi_error_redacts_submitted_secret_parameters(profile: Profile) -> None:
    password = "db-super-secret"
    opener = FakeOpener(
        FakeResponse({"result": {"status": 0, "errors": [f"rejected password {password}"]}})
    )
    with pytest.raises(UAPIError) as error:
        UAPITransport(opener=opener).call(
            profile,
            "token",
            "Mysql",
            "create_user",
            {"name": "account_user", "password": password},
            method="POST",
        )
    assert password not in str(error.value)


def test_uapi_error_redacts_policy_sensitive_names(profile: Profile) -> None:
    private_key = "dkim-private-secret"
    opener = FakeOpener(
        FakeResponse({"result": {"status": 0, "errors": [f"invalid key {private_key}"]}})
    )
    with pytest.raises(UAPIError) as error:
        UAPITransport(opener=opener).call(
            profile,
            "token",
            "Email",
            "install_dkim_private_keys",
            {"domain": "example.com", "dkim_private_key": private_key},
            method="POST",
            sensitive_names=("dkim_private_key",),
        )
    assert private_key not in str(error.value)


def test_uapi_error_redacts_explicit_resolved_secrets(profile: Profile) -> None:
    repository_url = "https://github.com/example/private-site.git"
    opener = FakeOpener(
        FakeResponse(
            {
                "result": {
                    "status": 0,
                    "errors": [f"failed to clone repository {repository_url}"],
                }
            }
        )
    )
    with pytest.raises(UAPIError) as error:
        UAPITransport(opener=opener).call(
            profile,
            "token",
            "VersionControl",
            "create",
            {"source_repository": f'{{"url":"{repository_url}"}}'},
            redaction_secrets=(repository_url,),
        )
    request = opener.requests[0][0]
    assert request.method == "POST"
    assert repository_url not in request.full_url
    assert repository_url not in str(error.value)
    assert "[REDACTED]" in str(error.value)


def test_partial_result_failures_raise_only_indexes_and_safe_messages(profile: Profile) -> None:
    private_key = "dkim-private-secret"
    opener = FakeOpener(
        FakeResponse(
            {
                "result": {
                    "status": 1,
                    "data": [
                        {"status": 1, "domain": "ok.example", "message": "created"},
                        {
                            "status": 0,
                            "domain": "bad.example",
                            "errors": [f"dkim import failed for {private_key}"],
                        },
                    ],
                }
            }
        )
    )
    with pytest.raises(PartialFailure) as error:
        UAPITransport(opener=opener).call(
            profile,
            "token",
            "Email",
            "install_dkim_private_keys",
            {"dkim_private_key": private_key},
            method="POST",
            sensitive_names=("dkim_private_key",),
        )
    message = str(error.value)
    assert "item 1" in message
    assert "dkim import failed" in message
    assert private_key not in message
    assert "item 0" not in message
    assert "ok.example" not in message
    assert "bad.example" not in message


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
