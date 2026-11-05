"""Streamlit page. Calls the backend only, never a source directly. See design.md, Architecture.

Run from the project folder: .venv\\Scripts\\python -m streamlit run frontend/app.py
(.streamlit/config.toml keeps it on 127.0.0.1:8501 and sets the dark theme.)

Every value that comes from a source is passed through esc() before it goes into HTML,
because names and tags come from outside and could contain markup.
"""

import os
from html import escape
from typing import Any
from urllib.parse import quote

import httpx
import streamlit as st
from dotenv import load_dotenv

from summary import SOURCE_LABELS, esc, safe_url, summarize, verdict

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
# Longer than the backend's per-source timeout, so the backend always answers first.
BACKEND_TIMEOUT = float(os.getenv("SOURCE_TIMEOUT_SECONDS", "10")) + 5

VERDICT_ICON = {"malicious": "●", "suspicious": "◐", "no_record": "○", "unknown": "◌"}
STATUS_CHIP = {  # status -> (css class, text)
    "ok": ("chip-ok", "record found"),
    "not_found": ("chip-none", "no record"),
    "unsupported": ("chip-none", "hash type not supported"),
    "error": ("chip-err", "error"),
}

CSS = """
<style>
:root { --cyan:#22d3ee; --panel:#111a2e; --line:#1e2a44; --muted:#8aa0bf; --red:#f87171; --amber:#fbbf24; --green:#34d399; }
.block-container { max-width: 1000px; padding-top: 2rem; }
.he-header { display:flex; align-items:baseline; justify-content:space-between; border-bottom:1px solid var(--line);
             padding-bottom:.6rem; margin-bottom:1.2rem; }
.he-brand { font-family: ui-monospace, Consolas, monospace; font-size:1.5rem; font-weight:700; letter-spacing:.08em; color:var(--cyan); }
.he-brand span { color:#e2e8f0; }
.he-tagline { color:var(--muted); font-size:.85rem; letter-spacing:.06em; text-transform:uppercase; }
.he-meta { font-family: ui-monospace, Consolas, monospace; color:var(--muted); font-size:.8rem; word-break:break-all; margin:.4rem 0 .8rem; }
.he-card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:1rem 1.2rem; margin-bottom:1rem; }
.he-label { color:var(--muted); font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; margin-bottom:.15rem; }
.he-value { font-size:1rem; margin-bottom:.7rem; }
.he-mono { font-family: ui-monospace, Consolas, monospace; }
.he-chips { display:flex; flex-wrap:wrap; gap:.5rem; margin:.2rem 0 1rem; }
.chip { font-family: ui-monospace, Consolas, monospace; font-size:.78rem; padding:.2rem .6rem; border-radius:999px; border:1px solid var(--line); }
.chip-ok { color:var(--red); border-color:rgba(248,113,113,.5); background:rgba(248,113,113,.08); }
.chip-none { color:var(--muted); }
.chip-err { color:var(--amber); border-color:rgba(251,191,36,.5); background:rgba(251,191,36,.08); }
.tag { display:inline-block; font-family: ui-monospace, Consolas, monospace; font-size:.78rem; padding:.1rem .5rem; margin:0 .3rem .3rem 0;
       border-radius:6px; background:#0b1220; border:1px solid var(--line); color:#cbd5e1; }
.tag-cve { color:var(--amber); border-color:rgba(251,191,36,.5); }
.he-note { color:var(--muted); font-size:.8rem; }
.verdict { display:flex; align-items:center; gap:1rem; border-radius:10px; padding:.9rem 1.2rem; margin-bottom:1rem; border:1px solid; }
.verdict-icon { font-size:1.6rem; line-height:1; }
.verdict-title { font-family: ui-monospace, Consolas, monospace; font-weight:700; letter-spacing:.06em; text-transform:uppercase; font-size:1.05rem; }
.verdict-detail { color:#cbd5e1; font-size:.88rem; }
.v-malicious { color:var(--red); border-color:rgba(248,113,113,.55); background:rgba(248,113,113,.08); }
.v-suspicious { color:var(--amber); border-color:rgba(251,191,36,.55); background:rgba(251,191,36,.08); }
.v-no_record { color:#cbd5e1; border-color:var(--line); background:var(--panel); }
.v-unknown { color:var(--muted); border-color:var(--line); background:var(--panel); border-style:dashed; }
.he-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:.2rem 1.4rem; }
.he-big { font-family: ui-monospace, Consolas, monospace; font-size:1.35rem; font-weight:700; color:#f8fafc; }
.he-card a { color:var(--cyan); text-decoration:none; }
</style>
"""


def tags_html(tags: list[Any]) -> str:
    if not tags:
        return '<span class="he-note">none</span>'
    return "".join(
        f'<span class="tag{" tag-cve" if str(t).lower().startswith("cve-") else ""}">{esc(t)}</span>' for t in tags
    )


def field(label: str, value_html: str) -> str:
    return f'<div class="he-label">{escape(label)}</div><div class="he-value">{value_html}</div>'


def card(inner_html: str) -> None:
    st.markdown(f'<div class="he-card">{inner_html}</div>', unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(page_title="hash-enrich", page_icon="🛡️", layout="centered")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown(
        '<div class="he-header"><div class="he-brand">▣ HASH<span>-ENRICH</span></div>'
        '<div class="he-tagline">threat intel lookup</div></div>',
        unsafe_allow_html=True,
    )

    with st.form("lookup", border=False):
        col_input, col_button = st.columns([5, 1], vertical_alignment="bottom")
        raw = col_input.text_input("File hash (MD5, SHA-1 or SHA-256)", placeholder="paste a hash…")
        submitted = col_button.form_submit_button("Scan", type="primary", use_container_width=True)
    if not submitted:
        st.markdown(
            '<div class="he-note">Sources: VirusTotal · MalwareBazaar · ThreatFox. '
            "Only the hash is sent, never a file. Lookups are not private.</div>",
            unsafe_allow_html=True,
        )
        return

    hash_value = raw.strip()  # pasted hashes often carry spaces or a newline
    if not hash_value:
        st.warning("Enter a hash.")
        return

    response = call_backend(hash_value)
    if response is None:
        return
    show_response(response)


def call_backend(hash_value: str) -> httpx.Response | None:
    url = f"{BACKEND_URL}/api/v1/hash/{quote(hash_value, safe='')}"
    try:
        with st.spinner("Scanning sources…"):
            return httpx.get(url, timeout=BACKEND_TIMEOUT)
    except httpx.ConnectError:
        st.error(f"Backend not running at {BACKEND_URL}")
    except httpx.TimeoutException:
        st.error(f"Backend at {BACKEND_URL} did not answer within {BACKEND_TIMEOUT:g} seconds")
    except httpx.HTTPError as exc:
        st.error(f"Could not reach the backend at {BACKEND_URL} ({type(exc).__name__})")
    return None


def show_response(response: httpx.Response) -> None:
    try:
        body = response.json()
    except ValueError:
        st.error(f"Backend returned HTTP {response.status_code} without a JSON body")
        return

    if response.status_code == 400:
        st.error(body.get("error", {}).get("message", "Invalid hash"))
        return
    if response.status_code not in (200, 502):
        st.error(f"Backend returned unexpected HTTP {response.status_code}")
        return

    st.markdown(
        f'<div class="he-meta">{esc(body["hash_type"]).upper()} {esc(body["hash"])} · queried {esc(body["queried_at"])}</div>',
        unsafe_allow_html=True,
    )
    show_overview(body)
    show_status_chips(body["sources"])
    show_source_tabs(body["sources"])


def show_overview(body: dict[str, Any]) -> None:
    sources = body["sources"]
    v = verdict(sources)
    st.markdown(
        f'<div class="verdict v-{v.level}"><div class="verdict-icon">{VERDICT_ICON[v.level]}</div>'
        f'<div><div class="verdict-title">{esc(v.title)}</div><div class="verdict-detail">{esc(v.detail)}</div></div></div>',
        unsafe_allow_html=True,
    )
    if v.level in ("no_record", "unknown"):
        return  # nothing to summarize

    s = summarize(sources)
    cells = []
    if s.family:
        aka = f' <span class="he-note">aka {esc(", ".join(s.aliases))}</span>' if s.aliases else ""
        cells.append(field("Malware family", f'<span class="he-big">{esc(s.family)}</span>{aka}'))
    if s.detections:
        malicious, counted = s.detections
        cells.append(field("VirusTotal detections", f'<span class="he-big">{malicious} / {counted}</span> <span class="he-note">engines</span>'))
    if s.threat_label or s.categories:
        cells.append(field("Classification", f'<span class="he-mono">{esc(s.threat_label)}</span> · {esc(", ".join(s.categories) or None)}'))
    if s.reputation is not None:
        cells.append(field("Community reputation", f"{esc(s.reputation)} <span class='he-note'>(negative = reported bad)</span>"))
    if s.threatfox:
        threat_type, confidence = s.threatfox
        cells.append(field("ThreatFox", f"{esc(threat_type)} · {esc(confidence)}% confidence"))
    if s.delivery or s.origin:
        cells.append(field("Delivery · origin", f"{esc(s.delivery)} · {esc(s.origin)}"))
    if s.first_seen:
        date, where = s.first_seen
        cells.append(field("First seen", f'{esc(date)} <span class="he-note">({esc(where)})</span>'))
    if s.last_analysis:
        cells.append(field("Last analysed", esc(s.last_analysis)))
    if s.cves:
        cells.append(field("Exploits", tags_html(s.cves)))
    if s.tags:
        cells.append(field("Tags", tags_html(s.tags)))
    if s.malpedia:
        cells.append(field("Reference", f'<a href="{esc(s.malpedia)}" target="_blank" rel="noopener noreferrer">Malpedia ↗</a>'))
    if cells:
        card(f'<div class="he-label" style="color:var(--cyan)">Summary</div><div class="he-grid">{"".join(f"<div>{c}</div>" for c in cells)}</div>')


def show_status_chips(sources: dict[str, Any]) -> None:
    chips = []
    for name, result in sources.items():
        css, text = STATUS_CHIP.get(result["status"], ("chip-none", result["status"]))
        chips.append(f'<span class="chip {css}">{esc(SOURCE_LABELS.get(name, name))}: {esc(text)}</span>')
    st.markdown(f'<div class="he-chips">{"".join(chips)}</div>', unsafe_allow_html=True)


def show_source_tabs(sources: dict[str, Any]) -> None:
    names = list(sources)
    tabs = st.tabs([SOURCE_LABELS.get(name, name) for name in names])
    for tab, name in zip(tabs, names):
        with tab:
            show_source(name, sources[name])


def show_source(name: str, result: dict[str, Any]) -> None:
    status = result["status"]
    if status == "ok":
        show_data = {
            "virustotal": show_virustotal,
            "malwarebazaar": show_malwarebazaar,
            "threatfox": show_threatfox,
        }.get(name, st.json)
        show_data(result["data"])
    elif status == "not_found":
        st.info("No record for this hash. This does not mean the file is safe.")
    elif status == "unsupported":
        st.info("This source does not accept this hash type.")
    else:
        error = result.get("error") or {}
        st.error(f"{error.get('code', 'error')}: {error.get('message', '')}")


def show_virustotal(data: dict[str, Any]) -> None:
    columns = st.columns(4)
    for column, key in zip(columns, ("malicious", "suspicious", "harmless", "undetected")):
        column.metric(key.capitalize(), data[key])
    names = data.get("names") or []
    shown = ", ".join(f'<span class="he-mono">{esc(n)}</span>' for n in names[:10])
    more = f' <span class="he-note">…and {len(names) - 10} more</span>' if len(names) > 10 else ""
    categories = ", ".join(data.get("threat_categories") or []) or None
    families = ", ".join(data.get("threat_names") or []) or None
    card(
        field("Threat label", f'<span class="he-mono">{esc(data.get("threat_label"))}</span>')
        + field("Category · families", f"{esc(categories)} · {esc(families)}")
        + field("Community reputation", f"{esc(data.get('reputation'))} <span class='he-note'>(negative = reported bad)</span>")
        + field("Tags", tags_html(data.get("tags") or []))
        + field("Type", esc(data.get("type_description")))
        + field(
            "First seen in the wild · first submitted · last analysed",
            f"{esc(data.get('first_seen_itw_date'))} · {esc(data.get('first_submission_date'))} · {esc(data.get('last_analysis_date'))}",
        )
        + field("Names", (shown + more) if names else "—")
    )
    st.caption("0 detections does not mean the file is safe.")
    st.link_button("Open in VirusTotal ↗", data["link"])


def show_malwarebazaar(data: dict[str, Any]) -> None:
    card(
        field("Malware family", f'<span class="he-mono">{esc(data.get("signature"))}</span>')
        + field("Tags", tags_html(data.get("tags") or []))
        + field("Delivery · origin", f"{esc(data.get('delivery_method'))} · {esc(data.get('origin_country'))}")
        + field("File type", esc(data.get("file_type")))
        + field("First seen · last seen", f"{esc(data.get('first_seen'))} · {esc(data.get('last_seen'))}")
    )


def show_threatfox(data: dict[str, Any]) -> None:
    matches = data.get("matches") or []
    for match in matches:
        malpedia = safe_url(match.get("malpedia"))
        reference = safe_url(match.get("reference"))
        links = []
        if malpedia:
            links.append(f'<a href="{esc(malpedia)}" target="_blank" rel="noopener noreferrer">Malpedia ↗</a>')
        if reference:
            links.append(f'<a href="{esc(reference)}" target="_blank" rel="noopener noreferrer">Reference ↗</a>')
        card(
            field(
                "Malware · alias",
                f'<span class="he-mono">{esc(match.get("malware_printable"))}</span> · {esc(match.get("malware_alias"))}',
            )
            + field("Threat type · confidence", f"{esc(match.get('threat_type'))} · {esc(match.get('confidence_level'))}%")
            + field("Tags", tags_html(match.get("tags") or []))
            + field("First seen · last seen", f"{esc(match.get('first_seen'))} · {esc(match.get('last_seen'))}")
            + (field("More", " · ".join(links)) if links else "")
        )
    st.caption(f"Listed as an IOC {len(matches)} time(s). ThreatFox drops IOCs after 6 months.")


main()
