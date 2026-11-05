"""Streamlit page. Calls the backend only, never a source directly. See design.md, Architecture.

Run from the project folder: .venv\\Scripts\\python -m streamlit run frontend/app.py
(.streamlit/config.toml keeps it on 127.0.0.1:8501.)
"""

import os
from typing import Any
from urllib.parse import quote

import httpx
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
# Longer than the backend's per-source timeout, so the backend always answers first.
BACKEND_TIMEOUT = float(os.getenv("SOURCE_TIMEOUT_SECONDS", "10")) + 5

SOURCE_LABELS = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox"}


def main() -> None:
    st.set_page_config(page_title="hash-enrich")
    st.title("hash-enrich")
    st.write("Look up a file hash (MD5, SHA-1 or SHA-256) in threat-intelligence sources.")

    with st.form("lookup"):
        raw = st.text_input("File hash")
        submitted = st.form_submit_button("Look up")
    if not submitted:
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
        with st.spinner("Looking up..."):
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

    st.caption(f"{body['hash_type'].upper()} {body['hash']} · queried {body['queried_at']}")
    if response.status_code == 502:
        st.warning("No source could answer. Each source's error is shown below.")
    for name, result in body["sources"].items():
        show_source(name, result)


def show_source(name: str, result: dict[str, Any]) -> None:
    st.subheader(SOURCE_LABELS.get(name, name))
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
    st.caption("0 detections does not mean the file is safe.")
    st.write(f"**Type:** {data.get('type_description') or 'unknown'}")
    st.write(f"**First submitted:** {data.get('first_submission_date') or 'unknown'}")
    names = data.get("names") or []
    if names:
        st.write("**Names:** " + ", ".join(f"`{n}`" for n in names[:20]))
        if len(names) > 20:
            st.caption(f"…and {len(names) - 20} more")
    st.link_button("Open in VirusTotal", data["link"])


def show_malwarebazaar(data: dict[str, Any]) -> None:
    st.write(f"**Malware family:** {data.get('signature') or 'unknown'}")
    tags = data.get("tags") or []
    st.write("**Tags:** " + (", ".join(f"`{t}`" for t in tags) if tags else "none"))
    st.write(f"**File type:** {data.get('file_type') or 'unknown'}")
    st.write(f"**First seen:** {data.get('first_seen') or 'unknown'} · **Last seen:** {data.get('last_seen') or 'unknown'}")


def show_threatfox(data: dict[str, Any]) -> None:
    matches = data.get("matches") or []
    st.write(f"Listed as an IOC {len(matches)} time(s).")
    st.dataframe(
        [
            {
                "Malware": m.get("malware_printable"),
                "Threat type": m.get("threat_type"),
                "Confidence": m.get("confidence_level"),
                "First seen": m.get("first_seen"),
                "Last seen": m.get("last_seen") or "",
            }
            for m in matches
        ],
        hide_index=True,
    )


main()
