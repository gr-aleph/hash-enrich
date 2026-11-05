"""Shared test setup. No test reaches the network.

Every source request goes to a fake HTTP client that routes it by host to a recorded real response
(tests/fixtures/<source>/<case>.json, saved by scripts/record.py) or to a simulated one.
"""

import json
import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.config import Settings, get_settings
from backend.main import app, get_client

FIXTURES = Path(__file__).parent / "fixtures"

FAKE_VT_KEY = "test-vt-key-not-real"
FAKE_ABUSECH_KEY = "test-abusech-key-not-real"

# The sample all three sources know (see scripts/record.py find), and a hash none of them know.
SAMPLE_SHA256 = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
SAMPLE_SHA1 = "78d23f781f3445fe820af8af266ca90850f60b85"
UNKNOWN_SHA256 = "0" * 64

HOSTS = {
    "www.virustotal.com": "virustotal",
    "mb-api.abuse.ch": "malwarebazaar",
    "threatfox-api.abuse.ch": "threatfox",
}

INVALID_HASH_BODY = {
    "error": {"code": "invalid_hash", "message": "Expected 32, 40 or 64 hex characters (MD5, SHA-1, SHA-256)"}
}


def load_fixture(source: str, case: str) -> dict:
    return json.loads((FIXTURES / source / f"{case}.json").read_text(encoding="utf-8"))


def recorded(source: str, case: str):
    """Replay a recorded real response."""
    fixture = load_fixture(source, case)

    def handler(request: httpx.Request) -> httpx.Response:
        body = fixture["body"]
        if isinstance(body, str):
            return httpx.Response(fixture["status_code"], text=body)
        return httpx.Response(fixture["status_code"], json=body)

    return handler


def simulated(status: int, body=None):
    """A made-up response, for cases that can't or shouldn't be recorded (429, 500)."""
    return lambda request: httpx.Response(status, json=body if body is not None else {})


def times_out(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("simulated timeout", request=request)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any test that tries to open a real connection (local loopback is still allowed)."""
    real_connect = socket.socket.connect

    def guarded_connect(sock, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(f"Test tried to reach the network: {address!r}")
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture
def api():
    """api(virustotal=handler, ...) returns a TestClient whose sources answer with the given handlers.

    Sources without a handler answer with their recorded "unknown" response.
    `client.calls[source]` lists the requests each source received.
    """
    calls = {name: [] for name in HOSTS.values()}

    def use(vt_key: str = FAKE_VT_KEY, abusech_key: str = FAKE_ABUSECH_KEY, **handlers) -> TestClient:
        routes = {name: recorded(name, "unknown") for name in calls} | handlers

        def route(request: httpx.Request) -> httpx.Response:
            name = HOSTS.get(request.url.host)
            assert name is not None, f"Unexpected host {request.url.host}"
            calls[name].append(request)
            return routes[name](request)

        async def fake_client():
            async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
                yield client

        app.dependency_overrides[get_client] = fake_client
        app.dependency_overrides[get_settings] = lambda: Settings(
            backend_port=8000, vt_api_key=vt_key, source_timeout_seconds=5, abusech_auth_key=abusech_key
        )
        client = TestClient(app)
        client.calls = calls
        return client

    yield use
    app.dependency_overrides.clear()


def lookup(client: TestClient, hash_value: str):
    """GET the hash endpoint; returns (HTTP status, parsed body)."""
    response = client.get(f"/api/v1/hash/{hash_value}")
    assert FAKE_VT_KEY not in response.text and FAKE_ABUSECH_KEY not in response.text
    return response.status_code, response.json()
