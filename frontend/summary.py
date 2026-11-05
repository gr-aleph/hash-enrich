"""Verdict badge, summary-card facts and HTML-safety helpers for the page.

Plain functions with no Streamlit code, so tests/test_summary.py can test them.
They only read the backend's response ("sources" object); they never call a source.
"""

from dataclasses import dataclass, field
from html import escape
from typing import Any

SOURCE_LABELS = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox"}

# A single antivirus engine flagging a file is often a false positive (design decision, Nov 2026).
KNOWN_MALICIOUS_MIN_ENGINES = 5


@dataclass(frozen=True)
class Verdict:
    level: str  # "malicious" | "suspicious" | "no_record" | "unknown"
    title: str
    detail: str


@dataclass
class Summary:
    family: str | None = None
    aliases: list[str] = field(default_factory=list)
    threat_label: str | None = None
    categories: list[str] = field(default_factory=list)
    detections: tuple[int, int] | None = None  # (malicious, engines with a verdict)
    reputation: int | None = None
    threatfox: tuple[str | None, int | None] | None = None  # (threat type, confidence %)
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # other tags, CVEs excluded
    delivery: str | None = None
    origin: str | None = None
    first_seen: tuple[str, str] | None = None  # (ISO date, source label), earliest across sources
    last_analysis: str | None = None
    malpedia: str | None = None


def _data(sources: dict[str, Any], name: str) -> dict[str, Any] | None:
    result = sources.get(name) or {}
    return result.get("data") if result.get("status") == "ok" else None


def verdict(sources: dict[str, Any]) -> Verdict:
    answered = [r for r in sources.values() if r.get("status") in ("ok", "not_found")]
    failed = [n for n, r in sources.items() if r.get("status") == "error"]
    if not answered:
        return Verdict("unknown", "Couldn't check", "Every source failed. See each source's tab for why.")

    vt = _data(sources, "virustotal")
    malicious = int(vt.get("malicious") or 0) if vt else 0
    reasons = []
    if malicious >= KNOWN_MALICIOUS_MIN_ENGINES:
        reasons.append(f"{malicious} VirusTotal engines flag it")
    reasons += [f"listed by {SOURCE_LABELS[n]}" for n in ("malwarebazaar", "threatfox") if _data(sources, n)]
    failed_note = f" {len(failed)} source(s) could not be checked." if failed else ""

    if reasons:
        text = "; ".join(reasons)
        return Verdict("malicious", "Known malicious", text[0].upper() + text[1:] + "." + failed_note)
    if malicious >= 1:
        return Verdict(
            "suspicious",
            "Suspicious",
            f"Only {malicious} VirusTotal engine(s) flag it, which can be a false positive.{failed_note}",
        )
    return Verdict(
        "no_record",
        "No record in any source",
        f"No detections or listings. This is not proof the file is safe.{failed_note}",
    )


def summarize(sources: dict[str, Any]) -> Summary:
    vt = _data(sources, "virustotal") or {}
    mb = _data(sources, "malwarebazaar") or {}
    tf_matches = (_data(sources, "threatfox") or {}).get("matches") or []
    tf = tf_matches[0] if tf_matches else {}

    summary = Summary()
    summary.family = mb.get("signature") or tf.get("malware_printable") or next(iter(vt.get("threat_names") or []), None)

    aliases = []
    for match in tf_matches:
        aliases += [a.strip() for a in str(match.get("malware_alias") or "").split(",") if a.strip()]
    summary.aliases = _unique([a for a in aliases if a.lower() != str(summary.family or "").lower()])

    summary.threat_label = vt.get("threat_label")
    summary.categories = list(vt.get("threat_categories") or [])
    if vt:
        counted = sum(int(vt.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
        summary.detections = (int(vt.get("malicious") or 0), counted)
    summary.reputation = vt.get("reputation")
    if tf:
        summary.threatfox = (tf.get("threat_type"), tf.get("confidence_level"))

    all_tags = _unique(list(vt.get("tags") or []) + list(mb.get("tags") or []) + list(tf.get("tags") or []))
    summary.cves = [t.upper() for t in all_tags if t.lower().startswith("cve-")]
    summary.tags = [t for t in all_tags if not t.lower().startswith("cve-")]

    summary.delivery = mb.get("delivery_method")
    summary.origin = mb.get("origin_country")

    seen = [
        (vt.get("first_seen_itw_date"), "VirusTotal, in the wild"),
        (vt.get("first_submission_date"), "VirusTotal, first submitted"),
        (mb.get("first_seen"), "MalwareBazaar"),
        (tf.get("first_seen"), "ThreatFox"),
    ]
    dated = [(date, label) for date, label in seen if date]
    summary.first_seen = min(dated) if dated else None  # ISO 8601 UTC strings sort by time
    summary.last_analysis = vt.get("last_analysis_date")
    summary.malpedia = safe_url(tf.get("malpedia"))
    return summary


def _unique(values: list[Any]) -> list[str]:
    """Keep the first spelling of each value, comparing case-insensitively."""
    seen, out = set(), []
    for value in values:
        text = str(value).strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


def esc(value: Any) -> str:
    """HTML-escape any value from a source; None or "" becomes an em dash."""
    return "—" if value is None or value == "" else escape(str(value))


def safe_url(value: Any) -> str | None:
    """Only http(s) links from sources are shown, never javascript: or other schemes."""
    text = str(value or "").strip()
    return text if text.lower().startswith(("https://", "http://")) else None
