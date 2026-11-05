"""Record real responses from VirusTotal, MalwareBazaar and ThreatFox for the tests.

Run from the project folder:

    .venv\\Scripts\\python scripts\\record.py find
        Prints a SHA-256 that all three sources know (taken from ThreatFox's IOCs of the last 7 days).

    .venv\\Scripts\\python scripts\\record.py record <sha256>
        Saves one JSON file per case in tests/fixtures/<source>/<case>.json.

Each file holds only {"status_code": ..., "body": ...}: never request headers, never a key.
Keys come from .env. Only hashes are sent; nothing is ever uploaded.
"""

import json
import os
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"

UNKNOWN_SHA256 = "0" * 64
BAD_KEY = "invalid-key-for-recording"
VT_PAUSE_SECONDS = 16  # free VirusTotal key: 4 requests a minute
TIMEOUT = 30


def load_keys() -> tuple[str, str]:
    load_dotenv(ROOT / ".env")
    vt_key = os.getenv("VT_API_KEY", "").strip()
    abusech_key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    for name, value in (("VT_API_KEY", vt_key), ("ABUSECH_AUTH_KEY", abusech_key)):
        if not value or value.startswith("your-"):
            sys.exit(f"{name} is not set in .env")
    return vt_key, abusech_key


def vt_get(client: httpx.Client, key: str, hash_value: str) -> httpx.Response:
    return client.get(VT_URL.format(hash=hash_value), headers={"x-apikey": key, "accept": "application/json"})


def mb_get_info(client: httpx.Client, key: str, hash_value: str) -> httpx.Response:
    return client.post(MB_URL, data={"query": "get_info", "hash": hash_value}, headers={"Auth-Key": key})


def tf_search_ioc(client: httpx.Client, key: str, hash_value: str) -> httpx.Response:
    # search_ioc finds the hash itself as an IOC. (search_hash would return IOCs *linked to* a sample.)
    return client.post(
        TF_URL,
        json={"query": "search_ioc", "search_term": hash_value, "exact_match": True},
        headers={"Auth-Key": key},
    )


def body_of(response: httpx.Response):
    try:
        return response.json()
    except ValueError:
        return response.text


def find(vt_key: str, abusech_key: str) -> None:
    with httpx.Client(timeout=TIMEOUT) as client:
        recent = client.post(TF_URL, json={"query": "get_iocs", "days": 7}, headers={"Auth-Key": abusech_key})
        iocs = body_of(recent)
        if not isinstance(iocs, dict) or iocs.get("query_status") != "ok":
            sys.exit(f"ThreatFox get_iocs failed: HTTP {recent.status_code}, {str(iocs)[:200]}")
        candidates = [i for i in iocs.get("data") or [] if i.get("ioc_type") == "sha256_hash"]
        print(f"ThreatFox has {len(candidates)} SHA-256 IOCs from the last 7 days. Checking them...")

        vt_checks = 0
        for ioc in candidates[:40]:
            sha256 = ioc["ioc"].strip().lower()
            mb = body_of(mb_get_info(client, abusech_key, sha256))
            if not (isinstance(mb, dict) and mb.get("query_status") == "ok"):
                continue
            if vt_checks:
                time.sleep(VT_PAUSE_SECONDS)
            vt_checks += 1
            if vt_get(client, vt_key, sha256).status_code == 200:
                print(f"Found: {sha256}  (ThreatFox: {ioc.get('malware_printable')})")
                return
            if vt_checks >= 3:
                break
    sys.exit("No hash found in all three sources. Try again later.")


def record(sha256: str, vt_key: str, abusech_key: str) -> None:
    sha256 = sha256.strip().lower()
    if len(sha256) != 64:
        sys.exit("Give a SHA-256 (64 hex characters), e.g. from: record.py find")

    secrets = [vt_key, abusech_key]
    results = []

    def save(source: str, case: str, response: httpx.Response) -> None:
        content = json.dumps({"status_code": response.status_code, "body": body_of(response)}, indent=2)
        if any(secret in content for secret in secrets):
            sys.exit(f"Stopped: a key appeared in the {source}/{case} response. Nothing was saved for it.")
        path = FIXTURES / source / f"{case}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content + "\n", encoding="utf-8")
        body = body_of(response)
        detail = ""
        if isinstance(body, dict):
            detail = body.get("query_status") or (body.get("error") or {}).get("code") or ""
        results.append((f"{source}/{case}.json", response.status_code, detail))

    with httpx.Client(timeout=TIMEOUT) as client:
        save("virustotal", "hit", vt_get(client, vt_key, sha256))
        time.sleep(VT_PAUSE_SECONDS)
        save("virustotal", "unknown", vt_get(client, vt_key, UNKNOWN_SHA256))

        hit = mb_get_info(client, abusech_key, sha256)
        save("malwarebazaar", "hit", hit)
        save("malwarebazaar", "unknown", mb_get_info(client, abusech_key, UNKNOWN_SHA256))
        try:
            sha1 = body_of(hit)["data"][0]["sha1_hash"]
        except (KeyError, IndexError, TypeError):
            sha1 = None
        if sha1:
            save("malwarebazaar", "sha1", mb_get_info(client, abusech_key, sha1))
        else:
            print("MalwareBazaar hit has no sha1_hash; skipped the SHA-1 recording.")
        save("malwarebazaar", "bad_key", mb_get_info(client, BAD_KEY, sha256))

        save("threatfox", "hit", tf_search_ioc(client, abusech_key, sha256))
        save("threatfox", "unknown", tf_search_ioc(client, abusech_key, UNKNOWN_SHA256))
        save("threatfox", "bad_key", tf_search_ioc(client, BAD_KEY, sha256))

    print(f"{'file':32} {'HTTP':>4}  status / error code")
    for name, status, detail in results:
        print(f"{name:32} {status:>4}  {detail}")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("find", "record"):
        sys.exit(__doc__)
    vt_key, abusech_key = load_keys()
    if sys.argv[1] == "find":
        find(vt_key, abusech_key)
    elif len(sys.argv) == 3:
        record(sys.argv[2], vt_key, abusech_key)
    else:
        sys.exit("Usage: record.py record <sha256>")


if __name__ == "__main__":
    main()
