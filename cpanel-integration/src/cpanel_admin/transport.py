"""Verified HTTPS transport for cPanel UAPI."""

from __future__ import annotations

import ipaddress
import json
import secrets
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .errors import TransportError, UAPIError, UsageError
from .profiles import Profile
from .redaction import redact

MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class ResponseLike(Protocol):
    status: int

    def __enter__(self) -> ResponseLike: ...

    def __exit__(self, *args: object) -> None: ...

    def read(self, size: int = -1) -> bytes: ...


class OpenerLike(Protocol):
    def open(self, request: Request, timeout: int) -> ResponseLike: ...


@dataclass(frozen=True)
class UAPIResponse:
    data: object
    warnings: list[str]
    messages: list[str]


@dataclass(frozen=True)
class Upload:
    filename: str
    content: bytes
    content_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        if (
            not self.filename
            or self.filename in {".", ".."}
            or any(character in self.filename for character in '/\\\r\n"')
        ):
            raise UsageError("Upload filename is invalid")
        if not isinstance(self.content, bytes):
            raise UsageError("Upload content must be bytes")
        if not self.content_type or any(character in self.content_type for character in "\r\n"):
            raise UsageError("Upload content type is invalid")


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


class SameOriginRedirectHandler(HTTPRedirectHandler):
    """Allow redirects only when scheme, hostname, and port remain identical."""

    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> Request | None:
        if _origin(req.full_url) != _origin(newurl):
            raise TransportError("Refusing cPanel redirect to a different origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _host_for_url(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{address}]" if address.version == 6 else str(address)


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _multipart_body(
    parameters: Mapping[str, object], files: Mapping[str, Upload]
) -> tuple[bytes, str]:
    boundary = f"cpanel-admin-{secrets.token_hex(16)}"
    marker = boundary.encode("ascii")
    body = bytearray()
    for name, value in parameters.items():
        if any(character in name for character in '\r\n"'):
            raise UsageError("Multipart parameter name is invalid")
        values = value if isinstance(value, list | tuple) else [value]
        for item in values:
            body.extend(b"--" + marker + b"\r\n")
            body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            body.extend(str(item).encode("utf-8"))
            body.extend(b"\r\n")
    for name, upload in files.items():
        if any(character in name for character in '\r\n"'):
            raise UsageError("Multipart file field name is invalid")
        body.extend(b"--" + marker + b"\r\n")
        body.extend(
            (
                f'Content-Disposition: form-data; name="{name}"; filename="{upload.filename}"\r\n'
            ).encode()
        )
        body.extend(f"Content-Type: {upload.content_type}\r\n\r\n".encode())
        body.extend(upload.content)
        body.extend(b"\r\n")
    body.extend(b"--" + marker + b"--\r\n")
    return bytes(body), boundary


class UAPITransport:
    """Call fixed UAPI operations and normalize their JSON envelope."""

    def __init__(self, opener: OpenerLike | None = None) -> None:
        if opener is None:
            context = ssl.create_default_context()
            opener = build_opener(
                SameOriginRedirectHandler(),
                HTTPSHandler(context=context),
            )
        self._opener = opener

    def call(
        self,
        profile: Profile,
        token: str,
        module: str,
        function: str,
        parameters: Mapping[str, object],
        timeout: int = 30,
        *,
        method: str = "GET",
        files: Mapping[str, Upload] | None = None,
    ) -> UAPIResponse:
        if not 1 <= timeout <= 120:
            raise UsageError("Timeout must be between 1 and 120 seconds")
        if not module.isidentifier() or not function.isidentifier():
            raise UsageError("Invalid UAPI operation identifier")
        base = f"https://{_host_for_url(profile.host)}:{profile.port}/execute/{module}/{function}"
        if method not in {"GET", "POST"}:
            raise UsageError("UAPI request method must be GET or POST")
        if files and method != "POST":
            raise UsageError("File uploads require a POST request")
        headers = {
            "Authorization": f"cpanel {profile.username}:{token}",
            "Accept": "application/json",
            "User-Agent": "cpanel-account-admin/0.1",
        }
        data: bytes | None = None
        if files:
            data, boundary = _multipart_body(parameters, files)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            url = base
        elif method == "POST":
            data = urlencode(parameters, doseq=True).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            url = base
        else:
            query = urlencode(parameters, doseq=True)
            url = f"{base}?{query}" if query else base
        request = Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                if not 200 <= response.status < 300:
                    raise TransportError(f"cPanel returned HTTP {response.status}")
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise TransportError(f"cPanel returned HTTP {exc.code}") from exc
        except URLError as exc:
            reason = exc.reason
            if isinstance(reason, socket.timeout):
                raise TransportError("cPanel request timed out") from exc
            if isinstance(reason, ssl.SSLError):
                raise TransportError("cPanel TLS verification failed") from exc
            safe_reason = redact(str(reason), secrets=(token,))
            raise TransportError(f"Network request failed: {safe_reason}") from exc
        except TimeoutError as exc:
            raise TransportError("cPanel request timed out") from exc
        except ssl.SSLError as exc:
            raise TransportError("cPanel TLS verification failed") from exc
        except TransportError:
            raise
        except OSError as exc:
            safe_reason = redact(str(exc), secrets=(token,))
            raise TransportError(f"Network request failed: {safe_reason}") from exc
        if len(body) > MAX_RESPONSE_BYTES:
            raise TransportError("cPanel response exceeds the 10 MiB safety limit")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransportError("cPanel response is not a valid JSON object") from exc
        if not isinstance(payload, dict):
            raise TransportError("cPanel response is not a valid JSON object")
        result = payload.get("result", payload)
        if not isinstance(result, dict):
            raise TransportError("cPanel response has an invalid UAPI result")
        if result.get("status") != 1:
            errors = _string_list(result.get("errors"))
            reason = "; ".join(errors) or "cPanel UAPI operation failed"
            safe_reason = redact(reason, secrets=(token,))
            raise UAPIError(str(safe_reason))
        return UAPIResponse(
            data=result.get("data"),
            warnings=_string_list(result.get("warnings")),
            messages=_string_list(result.get("messages")),
        )
