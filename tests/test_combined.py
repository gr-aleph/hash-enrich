"""All three sources together: one failing source must not hide the others (design.md, 200 and 502 rules)."""

import pytest

from conftest import SAMPLE_SHA256, UNKNOWN_SHA256, lookup, recorded, simulated, times_out
from backend.models import SourceResult
from backend.sources import SOURCES

ALL_HITS = {name: recorded(name, "hit") for name in ("virustotal", "malwarebazaar", "threatfox")}


def statuses(body):
    return {name: result["status"] for name, result in body["sources"].items()}


def test_all_three_sources_found(api):
    status, body = lookup(api(**ALL_HITS), SAMPLE_SHA256)
    assert status == 200
    assert statuses(body) == {"virustotal": "ok", "malwarebazaar": "ok", "threatfox": "ok"}


def test_all_three_sources_unknown(api):
    status, body = lookup(api(), UNKNOWN_SHA256)  # every source replays its recorded "unknown" response
    assert status == 200
    assert statuses(body) == {"virustotal": "not_found", "malwarebazaar": "not_found", "threatfox": "not_found"}


@pytest.mark.parametrize("failing", ["virustotal", "malwarebazaar", "threatfox"])
def test_one_failing_source_still_returns_the_other_two(api, failing):
    status, body = lookup(api(**(ALL_HITS | {failing: times_out})), SAMPLE_SHA256)
    assert status == 200
    assert body["sources"][failing]["status"] == "error"
    assert body["sources"][failing]["error"]["code"] == "timeout"
    for name, result in body["sources"].items():
        if name != failing:
            assert result["status"] == "ok"
            assert result["data"]


def test_all_sources_failing_returns_502_with_each_error(api):
    status, body = lookup(
        api(virustotal=simulated(429), malwarebazaar=recorded("malwarebazaar", "bad_key"), threatfox=times_out),
        SAMPLE_SHA256,
    )
    assert status == 502
    assert {name: r["error"]["code"] for name, r in body["sources"].items()} == {
        "virustotal": "rate_limited",
        "malwarebazaar": "auth_failed",
        "threatfox": "timeout",
    }


def test_unsupported_plus_errors_returns_502(api, monkeypatch):
    # No current source returns "unsupported", but the contract's 502 rule must still count it as "no answer".
    async def unsupported(hash_value, hash_type, client, settings):
        return SourceResult(status="unsupported")

    monkeypatch.setitem(SOURCES, "threatfox", unsupported)
    status, body = lookup(api(virustotal=times_out, malwarebazaar=simulated(500)), SAMPLE_SHA256)
    assert status == 502
    assert statuses(body) == {"virustotal": "error", "malwarebazaar": "error", "threatfox": "unsupported"}


def test_bug_in_one_source_becomes_its_error(api, monkeypatch):
    async def broken(hash_value, hash_type, client, settings):
        raise ZeroDivisionError

    monkeypatch.setitem(SOURCES, "threatfox", broken)
    status, body = lookup(api(**ALL_HITS), SAMPLE_SHA256)
    assert status == 200
    assert body["sources"]["threatfox"]["error"]["code"] == "upstream_error"
    assert body["sources"]["virustotal"]["status"] == "ok"
