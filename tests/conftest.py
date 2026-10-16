"""Shared fixtures. Every test runs with outbound networking blocked."""

import socket

import pytest


class NetworkBlockedError(RuntimeError):
    """Raised if any test (or code under test) tries to open a network connection."""


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Fail loudly if anything tries to reach the network during a test."""

    def _deny(*args, **kwargs):
        raise NetworkBlockedError("Network access is blocked in SentinelBox tests")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


@pytest.fixture
def client():
    """In-process test client: requests never leave the Python process."""
    from fastapi.testclient import TestClient

    from sentinelbox.mock_ai.app import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
