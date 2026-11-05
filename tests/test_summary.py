"""Verdict badge and summary card (frontend/summary.py). Bodies come from the backend replaying recorded
responses, or are built by hand for cases the recordings don't cover."""

import pytest

from conftest import SAMPLE_SHA256, UNKNOWN_SHA256, lookup, recorded, simulated, times_out
from frontend.summary import esc, safe_url, summarize, verdict

ALL_HITS = {name: recorded(name, "hit") for name in ("virustotal", "malwarebazaar", "threatfox")}


def sources_from(api, hash_value=SAMPLE_SHA256, **handlers):
    _, body = lookup(api(**handlers), hash_value)
    return body["sources"]


def vt_only(malicious: int) -> dict:
    """VirusTotal found the file with `malicious` detections; the abuse.ch sources have no record."""
    stats = {"malicious": malicious, "suspicious": 0, "harmless": 0, "undetected": 60 - malicious}
    return {
        "virustotal": {"status": "ok", "data": stats, "error": None},
        "malwarebazaar": {"status": "not_found", "data": None, "error": None},
        "threatfox": {"status": "not_found", "data": None, "error": None},
    }


# ---------- verdict ----------


def test_verdict_known_malicious_from_recordings(api):
    v = verdict(sources_from(api, **ALL_HITS))
    assert (v.level, v.title) == ("malicious", "Known malicious")
    assert v.detail == "49 VirusTotal engines flag it; listed by MalwareBazaar; listed by ThreatFox."


@pytest.mark.parametrize("malicious, level", [(5, "malicious"), (4, "suspicious"), (1, "suspicious"), (0, "no_record")])
def test_verdict_virustotal_threshold(malicious, level):
    assert verdict(vt_only(malicious)).level == level


def test_verdict_listing_alone_is_known_malicious():
    sources = vt_only(0)
    sources["threatfox"] = {"status": "ok", "data": {"matches": []}, "error": None}
    assert verdict(sources).level == "malicious"


def test_verdict_no_record_from_recordings(api):
    v = verdict(sources_from(api, UNKNOWN_SHA256))  # every source replays its recorded "unknown"
    assert (v.level, v.title) == ("no_record", "No record in any source")
    assert "not proof the file is safe" in v.detail


def test_verdict_no_record_mentions_failed_sources(api):
    v = verdict(sources_from(api, UNKNOWN_SHA256, virustotal=times_out))
    assert v.level == "no_record"
    assert "1 source(s) could not be checked" in v.detail


def test_verdict_malicious_even_if_virustotal_fails(api):
    v = verdict(sources_from(api, **(ALL_HITS | {"virustotal": simulated(401)})))
    assert v.level == "malicious"
    assert "1 source(s) could not be checked" in v.detail


def test_verdict_couldnt_check_when_all_fail(api):
    v = verdict(sources_from(api, virustotal=times_out, malwarebazaar=simulated(500), threatfox=simulated(429)))
    assert (v.level, v.title) == ("unknown", "Couldn't check")


# ---------- summary card ----------


def test_summary_from_recordings(api):
    s = summarize(sources_from(api, **ALL_HITS))
    assert s.family == "Mirai"
    assert s.aliases == ["Katana"]
    assert s.threat_label == "trojan.mozi/mirai"
    assert s.categories == ["trojan"]
    assert s.detections == (49, 64)
    assert s.reputation == -12
    assert s.threatfox == ("payload", 90)
    assert s.cves == ["CVE-2017-17215"]
    assert s.tags == ["upx", "elf", "exploit", "Mirai"]
    assert (s.delivery, s.origin) == ("web_download", "DE")
    assert s.first_seen == ("2026-04-17T11:47:11Z", "MalwareBazaar")
    assert s.last_analysis is not None and s.last_analysis.endswith("Z")
    assert s.malpedia == "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai"


def test_summary_falls_back_when_abusech_has_no_record(api):
    s = summarize(sources_from(api, virustotal=recorded("virustotal", "hit")))
    assert s.family == "mozi"  # VirusTotal's most common threat name
    assert s.aliases == []
    assert s.delivery is None and s.threatfox is None


# ---------- HTML safety ----------


def test_esc_escapes_markup():
    assert esc('<script>alert("x")</script>') == "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    assert esc(None) == "—"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("https://malpedia.caad.fkie.fraunhofer.de/x", "https://malpedia.caad.fkie.fraunhofer.de/x"),
        ("javascript:alert(1)", None),
        ("data:text/html,hi", None),
        (None, None),
    ],
)
def test_safe_url_allows_only_http(value, expected):
    assert safe_url(value) == expected
