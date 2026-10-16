"""Test doubles for the Stage 2 runner. No sockets are ever opened here."""

from __future__ import annotations

import itertools
import json
from datetime import datetime, timedelta, timezone

from sentinelbox.runner.transport import TransportResponse

BASE_URL = "http://127.0.0.1:8001"


def body_for(text: str = "Hello from the fake target.", **extra) -> bytes:
    return json.dumps({"model": "fake-1", "response": text, **extra}).encode("utf-8")


def ok(text: str = "Hello from the fake target.", **extra) -> TransportResponse:
    return TransportResponse(200, body_for(text, **extra))


def raw(status: int, body: bytes | str = b"", truncated: bool = False) -> TransportResponse:
    return TransportResponse(status, body.encode("utf-8") if isinstance(body, str) else body, truncated)


class FakeTransport:
    """Scripted transport.

    ``script`` is a list consumed in order (the last item repeats once the
    list runs out). An item is a TransportResponse, an exception instance (raised),
    or a callable ``(payload) -> TransportResponse | Exception``.
    """

    def __init__(self, script=None):
        self.script = list(script) if script is not None else [ok()]
        self.calls: list[dict] = []

    def post_json(self, url, payload, timeout):
        self.calls.append({"url": url, "payload": payload, "timeout": timeout})
        index = min(len(self.calls) - 1, len(self.script) - 1)
        item = self.script[index]
        if callable(item):
            item = item(payload)
        if isinstance(item, BaseException):
            raise item
        return item


class MockAppTransport:
    """Adapts the in-process Starlette TestClient to the runner's Transport protocol."""

    def __init__(self, client):
        self.client = client
        self.payloads: list[dict] = []

    def post_json(self, url, payload, timeout):
        assert url.endswith("/chat")
        self.payloads.append(payload)
        response = self.client.post("/chat", json=payload)
        return TransportResponse(response.status_code, response.content)


def fake_clock(start=None, step_seconds=1.0):
    moment = start or datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    counter = itertools.count()
    return lambda: moment + timedelta(seconds=step_seconds * next(counter))


def fake_timer(step=0.125):
    """Each call advances by *step* seconds; the runner calls it twice per case, so every case
    measures exactly step seconds (125.0 ms by default)."""
    counter = itertools.count()
    return lambda: next(counter) * step
