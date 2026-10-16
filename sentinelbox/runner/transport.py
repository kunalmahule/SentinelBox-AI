"""HTTP transport for the runner (the only module that touches the network stack).

Safety properties, all covered by tests:

* Only loopback targets are accepted (``127.0.0.0/8``, ``::1``, ``localhost``).
* Redirects are never followed, so a loopback server cannot bounce the runner elsewhere.
* Environment proxy settings are ignored, so traffic cannot be routed off-machine.
* The response body is size-capped.
* Every failure is mapped to a small set of typed errors; nothing is retried.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

MAX_BODY_BYTES = 1_048_576  # 1 MiB
CHAT_PATH = "/chat"


class TargetUrlError(ValueError):
    """The target URL is malformed or not a loopback address."""


class TransportError(Exception):
    """Base class for transport failures."""


class TransportTimeout(TransportError):
    pass


class TransportConnectionError(TransportError):
    pass


@dataclass(frozen=True)
class TransportResponse:
    status: int
    body: bytes
    truncated: bool = False


class Transport(Protocol):
    def post_json(self, url: str, payload: dict, timeout: float) -> TransportResponse: ...


def validate_target_url(base_url: str) -> str:
    """Return a normalised ``scheme://host[:port]`` or raise TargetUrlError."""
    try:
        parts = urlsplit(base_url.strip())
        port = parts.port  # may raise ValueError
    except ValueError as exc:
        raise TargetUrlError(f"Invalid target URL: {exc}") from exc
    if parts.scheme != "http":
        raise TargetUrlError("Target URL must start with http:// (loopback targets only)")
    if parts.username or parts.password:
        raise TargetUrlError("Target URL must not contain credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise TargetUrlError("Target URL must be a bare origin such as http://127.0.0.1:8001")
    host = parts.hostname
    if not host:
        raise TargetUrlError("Target URL has no host")
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise TargetUrlError(f"Refusing target {host!r}; use 127.0.0.1, ::1 or localhost") from None
        if not address.is_loopback:
            raise TargetUrlError(f"Refusing non-loopback target {host!r}; Stage 2 runs locally only")
    netloc = f"[{host}]" if ":" in host else host
    return f"http://{netloc}" + (f":{port}" if port is not None else "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None  # surfaces the 3xx as an HTTPError instead of following it


class UrllibTransport:
    """Real transport using the standard library only."""

    def __init__(self) -> None:
        # ProxyHandler({}) disables proxies taken from the environment.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def post_json(self, url: str, payload: dict, timeout: float) -> TransportResponse:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, method="POST", headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        try:
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    return self._read(response.status, response)
            except urllib.error.HTTPError as err:  # non-2xx (and unfollowed 3xx) are still responses
                with err:
                    return self._read(err.code, err)
        except TimeoutError as exc:
            raise TransportTimeout(f"Timed out after {timeout:g}s") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise TransportTimeout(f"Timed out after {timeout:g}s") from exc
            raise TransportConnectionError(f"Connection failed: {exc.reason}") from exc
        except OSError as exc:
            raise TransportConnectionError(f"Connection failed: {exc}") from exc
        except Exception as exc:  # e.g. malformed HTTP framing from a misbehaving server
            raise TransportConnectionError(f"Unexpected transport failure: {type(exc).__name__}: {exc}") from exc

    @staticmethod
    def _read(status: int, stream) -> TransportResponse:
        body = stream.read(MAX_BODY_BYTES + 1)
        truncated = len(body) > MAX_BODY_BYTES
        return TransportResponse(status=status, body=body[:MAX_BODY_BYTES], truncated=truncated)
