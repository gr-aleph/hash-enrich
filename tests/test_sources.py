"""Per-source tests. Hits, unknown hashes and bad keys replay recorded real responses;
429, 500 and timeouts are simulated. See design.md, Testing."""

import json
from urllib.parse import parse_qs

import pytest

from conftest import (
    FAKE_ABUSECH_KEY,
    FAKE_VT_KEY,
    SAMPLE_SHA1,
    SAMPLE_SHA256,
    UNKNOWN_SHA256,
    load_fixture,
    lookup,
    recorded,
    simulated,
    times_out,
)
from backend.sources.http import unix_to_iso


def source_result(client, source, hash_value=SAMPLE_SHA256):
    _, body = lookup(client, hash_value)
    return body["sources"][source]


# ---------- VirusTotal ----------


def test_virustotal_hit_recorded(api):
    client = api(virustotal=recorded("virustotal", "hit"))
    result = source_result(client, "virustotal")
    attributes = load_fixture("virustotal", "hit")["body"]["data"]["attributes"]
    stats = attributes["last_analysis_stats"]
    assert result["status"] == "ok"
    assert result["error"] is None
    data = result["data"]
    assert [data[k] for k in ("malicious", "suspicious", "harmless", "undetected")] == [
        stats["malicious"], stats["suspicious"], stats["harmless"], stats["undetected"]
    ]
    assert data["type_description"] == attributes["type_description"]
    assert data["names"] == attributes["names"]
    assert data["first_submission_date"] == unix_to_iso(attributes["first_submission_date"])
    assert data["link"] == f"https://www.virustotal.com/gui/file/{SAMPLE_SHA256}"
    # Optional threat details, from the same recording
    assert data["threat_label"] == "trojan.mozi/mirai"
    assert data["threat_categories"] == ["trojan"]
    assert data["threat_names"] == ["mozi", "mirai", "ddos"]
    assert data["reputation"] == -12
    assert data["tags"] == ["upx", "elf", "exploit", "cve-2017-17215"]
    assert data["last_analysis_date"] == unix_to_iso(attributes["last_analysis_date"])
    assert data["first_seen_itw_date"] == unix_to_iso(attributes["first_seen_itw_date"])
    [request] = client.calls["virustotal"]
    assert request.method == "GET"
    assert str(request.url) == f"https://www.virustotal.com/api/v3/files/{SAMPLE_SHA256}"
    assert request.headers["x-apikey"] == FAKE_VT_KEY


def test_virustotal_unknown_recorded(api):
    result = source_result(api(virustotal=recorded("virustotal", "unknown")), "virustotal", UNKNOWN_SHA256)
    assert result == {"status": "not_found", "data": None, "error": None}


@pytest.mark.parametrize(
    "handler, expected",
    [
        (simulated(401, {"error": {"code": "WrongCredentialsError", "message": "x"}}), "auth_failed"),
        (simulated(429, {"error": {"code": "QuotaExceededError", "message": "x"}}), "rate_limited"),
        (simulated(500), "upstream_error"),
        (simulated(403, {"error": {"code": "ForbiddenError", "message": "x"}}), "upstream_error"),
        (simulated(200, {"unexpected": True}), "upstream_error"),
        (times_out, "timeout"),
    ],
    ids=["401", "429", "500", "403", "bad-body", "timeout"],
)
def test_virustotal_errors(api, handler, expected):
    result = source_result(api(virustotal=handler), "virustotal")
    assert result["status"] == "error"
    assert result["data"] is None
    assert result["error"]["code"] == expected


def test_virustotal_missing_key_makes_no_call(api):
    client = api(vt_key="")
    assert source_result(client, "virustotal")["error"]["code"] == "missing_key"
    assert client.calls["virustotal"] == []


# ---------- MalwareBazaar ----------

MB_EXPECTED = {
    "signature": "Mirai",
    "tags": ["elf", "Mirai"],
    "file_type": "elf",
    "first_seen": "2026-04-17T11:47:11Z",
    "last_seen": "2026-07-14T08:24:54Z",
    "delivery_method": "web_download",
    "origin_country": "DE",
}


def test_malwarebazaar_hit_recorded(api):
    client = api(malwarebazaar=recorded("malwarebazaar", "hit"))
    assert source_result(client, "malwarebazaar") == {"status": "ok", "data": MB_EXPECTED, "error": None}
    [request] = client.calls["malwarebazaar"]
    assert request.method == "POST"
    assert str(request.url) == "https://mb-api.abuse.ch/api/v1/"
    assert request.headers["Auth-Key"] == FAKE_ABUSECH_KEY
    assert parse_qs(request.content.decode()) == {"query": ["get_info"], "hash": [SAMPLE_SHA256]}


def test_malwarebazaar_sha1_recorded(api):
    client = api(malwarebazaar=recorded("malwarebazaar", "sha1"))
    assert source_result(client, "malwarebazaar", SAMPLE_SHA1) == {"status": "ok", "data": MB_EXPECTED, "error": None}


def test_malwarebazaar_unknown_recorded(api):
    result = source_result(api(malwarebazaar=recorded("malwarebazaar", "unknown")), "malwarebazaar", UNKNOWN_SHA256)
    assert result == {"status": "not_found", "data": None, "error": None}


@pytest.mark.parametrize(
    "handler, expected",
    [
        (recorded("malwarebazaar", "bad_key"), "auth_failed"),
        (simulated(429), "rate_limited"),
        (simulated(500), "upstream_error"),
        (simulated(200, {"query_status": "illegal_hash"}), "upstream_error"),
        (simulated(200, {"query_status": "ok", "data": []}), "upstream_error"),
        (times_out, "timeout"),
    ],
    ids=["bad-key-recorded", "429", "500", "unknown-query-status", "bad-body", "timeout"],
)
def test_malwarebazaar_errors(api, handler, expected):
    result = source_result(api(malwarebazaar=handler), "malwarebazaar")
    assert result["status"] == "error"
    assert result["data"] is None
    assert result["error"]["code"] == expected


def test_malwarebazaar_missing_key_makes_no_call(api):
    client = api(abusech_key="")
    assert source_result(client, "malwarebazaar")["error"]["code"] == "missing_key"
    assert client.calls["malwarebazaar"] == []


# ---------- ThreatFox ----------

TF_EXPECTED = {
    "matches": [
        {
            "malware_printable": "Mirai",
            "threat_type": "payload",
            "confidence_level": 90,
            "first_seen": "2026-11-05T19:57:10Z",
            "last_seen": None,
            "malware_alias": "Katana",
            "tags": ["elf", "Mirai"],
            "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai",
            "reference": None,
        }
    ]
}


def test_threatfox_hit_recorded(api):
    client = api(threatfox=recorded("threatfox", "hit"))
    assert source_result(client, "threatfox") == {"status": "ok", "data": TF_EXPECTED, "error": None}
    [request] = client.calls["threatfox"]
    assert request.method == "POST"
    assert str(request.url) == "https://threatfox-api.abuse.ch/api/v1/"
    assert request.headers["Auth-Key"] == FAKE_ABUSECH_KEY
    assert json.loads(request.content) == {"query": "search_ioc", "search_term": SAMPLE_SHA256, "exact_match": True}


def test_threatfox_unknown_recorded(api):
    result = source_result(api(threatfox=recorded("threatfox", "unknown")), "threatfox", UNKNOWN_SHA256)
    assert result == {"status": "not_found", "data": None, "error": None}


def test_threatfox_accepts_sha1(api):
    client = api(threatfox=recorded("threatfox", "unknown"))
    assert source_result(client, "threatfox", SAMPLE_SHA1)["status"] == "not_found"
    assert json.loads(client.calls["threatfox"][0].content)["search_term"] == SAMPLE_SHA1


@pytest.mark.parametrize(
    "handler, expected",
    [
        (recorded("threatfox", "bad_key"), "auth_failed"),
        (simulated(429), "rate_limited"),
        (simulated(500), "upstream_error"),
        (simulated(200, {"query_status": "illegal_search_term"}), "upstream_error"),
        (simulated(200, {"query_status": "ok", "data": "not a list"}), "upstream_error"),
        (times_out, "timeout"),
    ],
    ids=["bad-key-recorded", "429", "500", "unknown-query-status", "bad-body", "timeout"],
)
def test_threatfox_errors(api, handler, expected):
    result = source_result(api(threatfox=handler), "threatfox")
    assert result["status"] == "error"
    assert result["data"] is None
    assert result["error"]["code"] == expected


def test_threatfox_missing_key_makes_no_call(api):
    client = api(abusech_key="")
    assert source_result(client, "threatfox")["error"]["code"] == "missing_key"
    assert client.calls["threatfox"] == []
