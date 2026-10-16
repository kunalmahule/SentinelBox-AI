"""Transport safety: loopback-only validation, error mapping and real-wire behaviour."""

import io
import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _socket
import pytest

from sentinelbox.runner.transport import (
    MAX_BODY_BYTES,
    TargetUrlError,
    TransportConnectionError,
    TransportTimeout,
    UrllibTransport,
    _NoRedirect,
    validate_target_url,
)

# Originals captured at import time, before the autouse fixture patches them.
_REAL_CONNECT = _socket.socket.connect
_REAL_CREATE_CONNECTION = socket.create_connection
_REAL_GETADDRINFO = socket.getaddrinfo


# --- URL validation ----------------------------------------------------------------
@pytest.mark.parametrize(
    "given, expected",
    [
        ("http://127.0.0.1:8001", "http://127.0.0.1:8001"),
        ("http://127.0.0.1:8001/", "http://127.0.0.1:8001"),
        ("  http://127.0.0.1:8001  ", "http://127.0.0.1:8001"),
        ("http://127.0.0.1", "http://127.0.0.1"),
        ("http://localhost:9000", "http://localhost:9000"),
        ("http://LOCALHOST:9000", "http://localhost:9000"),
        ("http://127.5.5.5:1", "http://127.5.5.5:1"),
        ("http://[::1]:8001", "http://[::1]:8001"),
    ],
)
def test_loopback_urls_are_accepted_and_normalised(given, expected):
    assert validate_target_url(given) == expected


@pytest.mark.parametrize(
    "given",
    [
        "https://127.0.0.1:8001", "ftp://127.0.0.1", "127.0.0.1:8001", "", "   ", "not a url", "http://",
        "http://example.com", "http://example.com:8001", "http://10.0.0.5:8001", "http://192.168.1.10",
        "http://0.0.0.0:8001", "http://8.8.8.8", "http://[2001:db8::1]:80", "http://127.0.0.1.evil.com",
        "http://localhost.evil.com", "http://2130706433", "http://user:pw@127.0.0.1:8001",
        "http://127.0.0.1:8001/chat", "http://127.0.0.1:8001/?x=1", "http://127.0.0.1:8001/#frag",
        "http://127.0.0.1:99999", "http://127.0.0.1:abc", "http://evil.com@127.0.0.1:8001@evil.com",
    ],
)
def test_non_loopback_or_malformed_urls_are_refused(given):
    with pytest.raises(TargetUrlError):
        validate_target_url(given)


def test_refusal_messages_explain_why():
    with pytest.raises(TargetUrlError, match="non-loopback"):
        validate_target_url("http://10.0.0.5")
    with pytest.raises(TargetUrlError, match="127.0.0.1, ::1 or localhost"):
        validate_target_url("http://example.com")
    with pytest.raises(TargetUrlError, match="http://"):
        validate_target_url("https://127.0.0.1")


# --- configuration of the real transport --------------------------------------------
def test_transport_ignores_environment_proxies_and_never_follows_redirects():
    opener = UrllibTransport()._opener
    # An empty ProxyHandler({}) registers no protocol methods, so urllib does not list it at all;
    # what matters is that no *active* proxy handler (one with proxies) is installed.
    # test_wire_environment_proxy_is_ignored proves the behaviour on a real connection.
    proxy_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert all(h.proxies == {} for h in proxy_handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers)
    assert any(isinstance(h, _NoRedirect) for h in opener.handlers)
    assert _NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://elsewhere/") is None


# --- error mapping with a stubbed opener -------------------------------------------------
class _FakeResponse:
    def __init__(self, status, body):
        self.status, self._stream = status, io.BytesIO(body)

    def read(self, n=-1):
        return self._stream.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, outcome):
        self.outcome, self.requests = outcome, []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def _transport_with(outcome):
    transport = UrllibTransport()
    transport._opener = _FakeOpener(outcome)
    return transport


def test_successful_reply_is_returned_with_status_and_body():
    transport = _transport_with(_FakeResponse(200, b'{"response": "hi"}'))
    reply = transport.post_json("http://127.0.0.1:1/chat", {"prompt": "p"}, 4.0)
    assert (reply.status, reply.body, reply.truncated) == (200, b'{"response": "hi"}', False)
    request, timeout = transport._opener.requests[0]
    assert timeout == 4.0 and request.get_method() == "POST"
    assert json.loads(request.data) == {"prompt": "p"}
    assert request.get_header("Content-type") == "application/json"


@pytest.mark.parametrize("code", [302, 400, 404, 422, 500, 503])
def test_http_error_statuses_are_returned_as_responses_not_raised(code):
    error = urllib.error.HTTPError("http://127.0.0.1:1/chat", code, "msg", {}, io.BytesIO(b"details"))
    reply = _transport_with(error).post_json("http://127.0.0.1:1/chat", {}, 1.0)
    assert (reply.status, reply.body) == (code, b"details")


def test_oversized_body_is_cut_at_the_limit_and_flagged():
    reply = _transport_with(_FakeResponse(200, b"x" * (MAX_BODY_BYTES + 5))).post_json("http://127.0.0.1:1/chat", {}, 1.0)
    assert reply.truncated is True and len(reply.body) == MAX_BODY_BYTES


class _EndlessResponse(_FakeResponse):
    """A server that never stops sending. Any unbounded read fails the test instead of eating memory."""

    def __init__(self):
        super().__init__(200, b"")

    def read(self, n=-1):
        assert n is not None and 0 <= n <= MAX_BODY_BYTES + 1, f"unbounded read requested: {n!r}"
        return b"x" * n


def test_body_is_read_with_a_bound_so_an_endless_stream_cannot_exhaust_memory():
    reply = _transport_with(_EndlessResponse()).post_json("http://127.0.0.1:1/chat", {}, 1.0)
    assert reply.truncated is True and len(reply.body) == MAX_BODY_BYTES


def test_body_of_exactly_the_limit_is_not_flagged():
    reply = _transport_with(_FakeResponse(200, b"x" * MAX_BODY_BYTES)).post_json("http://127.0.0.1:1/chat", {}, 1.0)
    assert reply.truncated is False and len(reply.body) == MAX_BODY_BYTES


@pytest.mark.parametrize(
    "failure, expected",
    [
        (TimeoutError("timed out"), TransportTimeout),
        (urllib.error.URLError(TimeoutError("timed out")), TransportTimeout),
        (urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")), TransportConnectionError),
        (urllib.error.URLError("no route"), TransportConnectionError),
        (ConnectionResetError("reset"), TransportConnectionError),
        (OSError("network unreachable"), TransportConnectionError),
        (RuntimeError("weird framing"), TransportConnectionError),
    ],
    ids=["timeout", "url-timeout", "refused", "url-reason-str", "reset", "oserror", "unexpected"],
)
def test_failures_are_mapped_to_typed_transport_errors(failure, expected):
    with pytest.raises(expected):
        _transport_with(failure).post_json("http://127.0.0.1:1/chat", {}, 1.0)


# --- real wire tests against a throwaway loopback stub server --------------------------------
def _is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture
def loopback_only(monkeypatch):
    """Relax the suite-wide network block for *loopback addresses only*."""

    def check(host):
        if not _is_loopback(host):
            raise RuntimeError(f"Network access is blocked in SentinelBox tests (not loopback: {host!r})")

    def connect(self, address):
        check(address[0])
        return _REAL_CONNECT(self, address)

    def create_connection(address, *args, **kwargs):
        check(address[0])
        return _REAL_CREATE_CONNECTION(address, *args, **kwargs)

    def getaddrinfo(host, *args, **kwargs):
        check(host)
        return _REAL_GETADDRINFO(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


class _StubServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.behavior = lambda handler, body: handler.reply(200, b'{"response": "stub"}')
        self.paths, self.received = [], []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def reply(self, status, body, headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.paths.append(self.path)
        self.server.received.append((dict(self.headers), body))
        self.server.behavior(self, body)

    do_GET = do_POST


@pytest.fixture
def stub(loopback_only):
    server = _StubServer()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_wire_guard_still_blocks_non_loopback_addresses(loopback_only):
    with pytest.raises(RuntimeError, match="not loopback"):
        socket.create_connection(("example.com", 80), timeout=1)
    with pytest.raises(RuntimeError, match="not loopback"):
        socket.getaddrinfo("example.com", 80)


def test_wire_successful_post_sends_json_and_returns_body(stub):
    reply = UrllibTransport().post_json(stub.url + "/chat", {"prompt": "hi", "mode": "hardened"}, 2.0)
    assert (reply.status, reply.body) == (200, b'{"response": "stub"}')
    headers, body = stub.received[0]
    assert json.loads(body) == {"prompt": "hi", "mode": "hardened"}
    assert headers["Content-Type"] == "application/json"


def test_wire_error_status_and_body_are_returned(stub):
    stub.behavior = lambda h, b: h.reply(500, b'{"detail": "server broke"}')
    reply = UrllibTransport().post_json(stub.url + "/chat", {}, 2.0)
    assert (reply.status, reply.body) == (500, b'{"detail": "server broke"}')


def test_wire_redirects_are_not_followed(stub):
    stub.behavior = lambda h, b: h.reply(302, b"", [("Location", stub.url + "/somewhere-else")])
    reply = UrllibTransport().post_json(stub.url + "/chat", {}, 2.0)
    assert reply.status == 302
    assert stub.paths == ["/chat"]  # the redirect target was never requested


def test_wire_environment_proxy_is_ignored(stub, monkeypatch):
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")  # a dead port: a proxied request would fail
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert UrllibTransport().post_json(stub.url + "/chat", {}, 2.0).status == 200


def test_wire_oversized_body_is_truncated(stub):
    stub.behavior = lambda h, b: h.reply(200, b"a" * (MAX_BODY_BYTES + 10))
    reply = UrllibTransport().post_json(stub.url + "/chat", {}, 5.0)
    assert reply.truncated is True and len(reply.body) == MAX_BODY_BYTES


def test_wire_slow_server_times_out(stub):
    stub.behavior = lambda h, b: (time.sleep(0.6), h.reply(200, b"{}"))
    started = time.perf_counter()
    with pytest.raises(TransportTimeout):
        UrllibTransport().post_json(stub.url + "/chat", {}, 0.2)
    assert time.perf_counter() - started < 0.55


def test_wire_connection_refused_is_a_connection_error(loopback_only):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    # The socket is closed again, so nothing is listening on that port.
    with pytest.raises(TransportConnectionError, match="refused|Connection"):
        UrllibTransport().post_json(f"http://127.0.0.1:{port}/chat", {}, 2.0)


def test_wire_server_that_hangs_up_without_replying_is_a_connection_error(stub):
    stub.behavior = lambda h, b: setattr(h, "close_connection", True)
    with pytest.raises(TransportConnectionError):
        UrllibTransport().post_json(stub.url + "/chat", {}, 2.0)


def test_wire_garbage_instead_of_http_is_a_connection_error(stub):
    stub.behavior = lambda h, b: h.wfile.write(b"THIS IS NOT HTTP\r\n\r\n")
    with pytest.raises(TransportConnectionError, match="Unexpected transport failure|Connection"):
        UrllibTransport().post_json(stub.url + "/chat", {}, 2.0)
