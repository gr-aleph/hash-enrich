"""API contract tests: health, the 400 body, and the 200 response shape. See design.md, API contract."""

import pytest

from conftest import INVALID_HASH_BODY, SAMPLE_SHA256, lookup, simulated

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Simulated, trimmed VirusTotal file object, to check the exact contract fields.
VT_SIMULATED_HIT = {
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


def test_network_guard_blocks_real_connections():
    import socket

    with pytest.raises(RuntimeError, match="tried to reach the network"):
        socket.create_connection(("192.0.2.1", 443), timeout=1)  # TEST-NET address, never routed


def test_health(api):
    response = api().get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("bad", ["xyz", "a" * 31, "a" * 33, "g" * 32, "a" * 65, " " + "a" * 31])
def test_invalid_hash_returns_400_and_calls_no_source(api, bad):
    client = api()
    response = client.get(f"/api/v1/hash/{bad}")
    assert response.status_code == 400
    assert response.json() == INVALID_HASH_BODY
    assert all(requests == [] for requests in client.calls.values())


@pytest.mark.parametrize(
    "value, hash_type",
    [
        ("44D88612FEA8A8F36DE82E1278ABB02F", "md5"),
        ("3395856ce81f2b7382dee72602f798b642f14140", "sha1"),
        (SAMPLE_SHA256, "sha256"),
    ],
)
def test_response_shape(api, value, hash_type):
    status, body = lookup(api(virustotal=simulated(200, VT_SIMULATED_HIT)), value)
    assert status == 200
    assert set(body) == {"hash", "hash_type", "queried_at", "sources"}
    assert body["hash"] == value.lower()
    assert body["hash_type"] == hash_type
    assert body["queried_at"].endswith("Z")
    for result in body["sources"].values():
        assert set(result) == {"status", "data", "error"}
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
