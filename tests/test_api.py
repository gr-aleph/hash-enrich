"""API contract tests for Milestone 1. No network calls: VirusTotal is simulated with httpx.MockTransport.

Milestone 2 replaces the simulated hit and not-found bodies with recorded real responses
in tests/fixtures/virustotal/.
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.config import Settings, get_settings
from backend.main import app, get_client

FAKE_KEY = "test-key-not-real"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Simulated, trimmed VirusTotal file object (not a recording).
VT_HIT = {
    "data": {
        "id": EICAR_SHA256,
        "type": "file",
        "attributes": {
            "sha256": EICAR_SHA256,
            "last_analysis_stats": {
                "malicious": 61, "suspicious": 0, "harmless": 0, "undetected": 11,
                "timeout": 0, "confirmed-timeout": 0, "type-unsupported": 3, "failure": 0,
            },
            "type_description": "Text",
            "names": ["eicar.com", "eicar.txt"],
            "first_submission_date": 1148282220,
        },
    }
}


@pytest.fixture
def calls():
    """Requests the fake VirusTotal received."""
    return []


@pytest.fixture
def api(calls):
    def use(handler, key=FAKE_KEY):
        def recording_handler(request):
            calls.append(request)
            return handler(request)

        async def fake_client():
            async with httpx.AsyncClient(transport=httpx.MockTransport(recording_handler)) as client:
                yield client

        app.dependency_overrides[get_client] = fake_client
        app.dependency_overrides[get_settings] = lambda: Settings(
            backend_port=8000, vt_api_key=key, source_timeout_seconds=5
        )
        return TestClient(app)

    yield use
    app.dependency_overrides.clear()


def respond(status, body=None):
    return lambda request: httpx.Response(status, json=body if body is not None else {})


def test_health(api):
    response = api(respond(200)).get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("bad", ["xyz", "a" * 31, "a" * 33, "g" * 32, "a" * 65, " " + "a" * 31])
def test_invalid_hash_returns_400_and_calls_no_source(api, calls, bad):
    response = api(respond(200, VT_HIT)).get(f"/api/v1/hash/{bad}")
    assert response.status_code == 400
    assert response.json() == {
        "error": {"code": "invalid_hash", "message": "Expected 32, 40 or 64 hex characters (MD5, SHA-1, SHA-256)"}
    }
    assert calls == []


@pytest.mark.parametrize(
    "value, hash_type",
    [(EICAR_MD5.upper(), "md5"), ("3395856ce81f2b7382dee72602f798b642f14140", "sha1"), (EICAR_SHA256, "sha256")],
)
def test_hit_returns_contract_shape(api, calls, value, hash_type):
    response = api(respond(200, VT_HIT)).get(f"/api/v1/hash/{value}")
    assert response.status_code == 200
    body = response.json()
    assert body["hash"] == value.lower()
    assert body["hash_type"] == hash_type
    assert body["queried_at"].endswith("Z")
    assert body["sources"]["virustotal"] == {
        "status": "ok",
        "data": {
            "malicious": 61, "suspicious": 0, "harmless": 0, "undetected": 11,
            "type_description": "Text",
            "names": ["eicar.com", "eicar.txt"],
            "first_submission_date": "2006-05-22T07:17:00Z",
            "link": f"https://www.virustotal.com/gui/file/{EICAR_SHA256}",
        },
        "error": None,
    }
    [request] = calls
    assert request.method == "GET"
    assert str(request.url) == f"https://www.virustotal.com/api/v3/files/{value.lower()}"
    assert request.headers["x-apikey"] == FAKE_KEY


def test_unknown_hash_is_not_found_with_200(api):
    response = api(respond(404, {"error": {"code": "NotFoundError", "message": "not found"}})).get(
        f"/api/v1/hash/{'0' * 64}"
    )
    assert response.status_code == 200
    assert response.json()["sources"]["virustotal"] == {"status": "not_found", "data": None, "error": None}


@pytest.mark.parametrize(
    "status, vt_code, expected",
    [
        (401, "WrongCredentialsError", "auth_failed"),
        (429, "QuotaExceededError", "rate_limited"),
        (500, None, "upstream_error"),
        (403, "ForbiddenError", "upstream_error"),
    ],
)
def test_source_error_returns_502(api, status, vt_code, expected):
    body = {"error": {"code": vt_code, "message": "x"}} if vt_code else None
    response = api(respond(status, body)).get(f"/api/v1/hash/{EICAR_MD5}")
    assert response.status_code == 502
    result = response.json()["sources"]["virustotal"]
    assert result["status"] == "error"
    assert result["data"] is None
    assert result["error"]["code"] == expected
    assert FAKE_KEY not in response.text


def test_timeout_returns_502(api):
    def slow(request):
        raise httpx.ReadTimeout("simulated timeout", request=request)

    response = api(slow).get(f"/api/v1/hash/{EICAR_MD5}")
    assert response.status_code == 502
    assert response.json()["sources"]["virustotal"]["error"]["code"] == "timeout"


def test_missing_key_returns_502_without_calling_virustotal(api, calls):
    response = api(respond(200, VT_HIT), key="").get(f"/api/v1/hash/{EICAR_MD5}")
    assert response.status_code == 502
    assert response.json()["sources"]["virustotal"]["error"]["code"] == "missing_key"
    assert calls == []


def test_unexpected_body_is_upstream_error(api):
    response = api(respond(200, {"unexpected": True})).get(f"/api/v1/hash/{EICAR_MD5}")
    assert response.status_code == 502
    assert response.json()["sources"]["virustotal"]["error"]["code"] == "upstream_error"
