# hash-enrich: design

Status: draft. Update this file whenever a decision changes.

## Goal

An analyst enters a file hash (MD5, SHA-1 or SHA-256) and sees enrichment from three real sources on one page, instead of opening a browser tab per source.

Users: one analyst on this laptop, a few lookups at a time. Later API callers, all on this laptop: an MCP server and my Sysmon portal. A classmate will later extend the code (caching); they do not call the API.

## Out of scope (this version)

Do not add any of these, even if they seem helpful:

- Database or any persistent storage
- Caching (added later by a classmate in Reading Unfamiliar Code)
- Privacy guard in code (added later in Secure Coding with AI; today it is a rule, see Source rules)
- Bulk or batch lookups, performance optimization
- File upload of any kind. The tool only ever sends a hash, never a file
- Authentication for the portal itself

## Architecture

```
Browser -> Streamlit frontend --HTTP JSON--> FastAPI backend --> VirusTotal / MalwareBazaar / ThreatFox
```

- **Frontend** (`frontend/`): Streamlit page with one input box. Calls the backend only. Trims spaces around the pasted hash. Shows one section per source, including its error. Backend-call timeout is `SOURCE_TIMEOUT_SECONDS + 5`; if the backend is unreachable, shows "Backend not running at BACKEND_URL", not a traceback.
- **Backend** (`backend/`): FastAPI app run with uvicorn on **127.0.0.1 only** (never `0.0.0.0`, never `fastapi run`). Validates the hash, calls all sources at the same time (`httpx.AsyncClient` + `asyncio.gather`), each with its own timeout, and returns the contract below.
- **Sources** (`backend/sources/`): one module per source; takes a hash, returns a normalized result or an error. Adding a source = adding a module.
- Two processes, no containers. Run each in its own terminal.

### Configuration (environment variables, loaded from `.env`)

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_PORT` | `8000` | Backend port on 127.0.0.1 (so two portals can run on one laptop) |
| `BACKEND_URL` | `http://127.0.0.1:8000` | Where the frontend finds the backend |
| `VT_API_KEY` | none | VirusTotal key |
| `ABUSECH_AUTH_KEY` | none | abuse.ch key (covers MalwareBazaar and ThreatFox) |
| `SOURCE_TIMEOUT_SECONDS` | `10` | Per-source request timeout |

The Streamlit page also listens on 127.0.0.1 only (`.streamlit/config.toml`, `address = "127.0.0.1"`), because it calls the backend with your key. Its port is 8501; run a second portal with `--server.port 8502`.
`.env` is in `.gitignore`. `.env.example` lists the variables with placeholder values only.

## API contract (v1)

### `GET /api/v1/hash/{hash}`

`hash`: 32, 40 or 64 hex characters (MD5, SHA-1, SHA-256), case-insensitive. The backend lowercases it and detects the type from its length.

**200 OK**: valid input and at least one source answered (`ok` or `not_found`).

```json
{
  "hash": "44d88612fea8a8f36de82e1278abb02f",
  "hash_type": "md5",
  "queried_at": "2026-11-05T18:00:00Z",
  "sources": {
    "virustotal":    {"status": "ok", "data": {"malicious": 61, "suspicious": 0, "harmless": 0, "undetected": 11, "type_description": "Text", "names": ["eicar.com"], "first_submission_date": "2006-05-22T07:17:00Z", "link": "https://www.virustotal.com/gui/file/..."}, "error": null},
    "malwarebazaar": {"status": "not_found", "data": null, "error": null},
    "threatfox":     {"status": "error", "data": null, "error": {"code": "rate_limited", "message": "ThreatFox returned 429 Too Many Requests"}}
  }
}
```

(Illustrative values. Replace with fields from a real recorded response.)

| Field | Meaning |
|---|---|
| `status` | `ok` (found), `not_found` (no record), `unsupported` (source does not accept this hash type), `error` (lookup failed) |
| `data` | Normalized fields when `status` is `ok`, otherwise `null` |
| `error.code` | `timeout`, `rate_limited`, `auth_failed`, `upstream_error`, `missing_key` |

`not_found` is not an error. "Not found" and "0 detections" do not mean "safe".

**`data` per source**
- VirusTotal: `malicious`, `suspicious`, `harmless`, `undetected` from `last_analysis_stats` (its other 4 keys are left out on purpose); `type_description`; `names`; `first_submission_date` converted from Unix timestamp to ISO 8601 UTC; `link` built as `https://www.virustotal.com/gui/file/<data.id>` (`data.id` is the SHA-256).
- MalwareBazaar (proposed, confirm by recording): `signature`, `tags`, `file_type`, `first_seen`, `last_seen`.
- ThreatFox (proposed, confirm by recording): `matches`, a list of `{malware_printable, threat_type, confidence_level, first_seen, last_seen}`.

**Status mapping**

| Result | VirusTotal | MalwareBazaar | ThreatFox |
|---|---|---|---|
| `ok` | HTTP 200 | `query_status` `ok` | `query_status` `ok` |
| `not_found` | HTTP 404 | `hash_not_found` | undocumented, confirm by recording |
| `unsupported` | never | never (see Open questions) | SHA-1, without calling ThreatFox |
| `auth_failed` | HTTP 401 | HTTP 401/403 or confirmed bad-key status | same as MalwareBazaar |
| `rate_limited` | HTTP 429 | HTTP 429 | HTTP 429 |
| `timeout` / `missing_key` | no answer in time / key empty, no request sent | same | same |
| `upstream_error` | anything else | anything else, incl. unknown `query_status` | same as MalwareBazaar |

**400 Bad Request**: invalid input, no source called. A custom handler replaces FastAPI's default 422.

```json
{"error": {"code": "invalid_hash", "message": "Expected 32, 40 or 64 hex characters (MD5, SHA-1, SHA-256)"}}
```

**502 Bad Gateway**: no source returned `ok` or `not_found`. Same body shape as 200. In Milestone 1 (VirusTotal only), a VirusTotal error means 502.

### `GET /api/v1/health`

`200 {"status": "ok"}`. FastAPI also serves docs at `/docs`; this section is the contract, so if they disagree, fix the code.

## Data sources

Checked against official docs on 5 Nov 2026: [VirusTotal](https://docs.virustotal.com/reference/file-info) ([errors](https://docs.virustotal.com/reference/errors), [limits](https://docs.virustotal.com/reference/public-vs-premium-api)), [MalwareBazaar](https://bazaar.abuse.ch/api/), [ThreatFox](https://threatfox.abuse.ch/api/), [abuse.ch keys](https://auth.abuse.ch/).

| Source | Request | Limits | Hash types | Notes |
|---|---|---|---|---|
| VirusTotal | `GET https://www.virustotal.com/api/v3/files/{hash}`, header `x-apikey` | 4/min, 500/day | MD5, SHA-1, SHA-256 | Free key; not for commercial use. **Never** call `POST /api/v3/files` (upload). |
| MalwareBazaar | `POST https://mb-api.abuse.ch/api/v1/`, form `query=get_info&hash=...`, header `Auth-Key` | Fair use | Docs say all three but contradict themselves | Free abuse.ch key, mandatory since 30 Jun 2025. |
| ThreatFox | `POST https://threatfox-api.abuse.ch/api/v1/`, JSON `{"query": "search_hash", "hash": "..."}`, header `Auth-Key` | Fair use | MD5, SHA-256 only | Same key. IOCs older than 6 months are not returned. |

On HTTP 429 return `rate_limited`; do not retry in a loop.

## Source rules

- API keys live only in `.env` or environment variables. Never in code, tests, recordings or commits.
- The repository is public: a committed key counts as stolen. Revoke it and create a new one; deleting the commit is not enough.
- Never upload files anywhere. Hash lookups only.
- Lookups are not private. Never look up hashes of internal or private files.
- Expect failures (timeouts, 429, source down, missing or wrong key). Each becomes that source's `error`, never a crash.

## Testing

- `pytest`, no network calls; tests must pass with the network off.
- Hit and unknown hash: recorded real responses in `tests/fixtures/<source>/`, saved by `scripts/record.py` (response body only, no request headers).
- Errors (timeout, 429, 401): simulated with `httpx.MockTransport`. Contract shape (200, 400, 502) tested with FastAPI's `TestClient`.
- Before committing a fixture: `git grep -n -i -E "x-apikey|auth-key|<first 6 chars of your key>"`.

## Decisions

| Decision | Reason |
|---|---|
| Accept MD5, SHA-1, SHA-256; detect type by length | Analysts get all three from reports. |
| FastAPI + uvicorn backend, custom 400 handler | Input validation and `/docs` for later callers; contract promises 400, not 422. |
| Streamlit frontend | Pure Python UI. Tradeoff: many dependencies. |
| `httpx` | Timeouts, async, and `MockTransport` for tests. |
| Bind 127.0.0.1 only | All callers are local and there is no login; wider binding exposes the keys' quota. |
| Call sources at the same time | Worst case one timeout, not three. |
| 502 only when no source answered | `unsupported` + `error` tells the caller nothing. |
| Frontend trims whitespace, API strict | Pasted hashes carry spaces; other callers get a clear 400. |
| Recorded hits, simulated errors | Timeouts can't be recorded; real 429s waste quota. |
| Plain JSON fixtures, no recording library | Easy to check for keys; libraries can save request headers. |
| Per-source `status`, versioned `/api/v1/` | One failing source can't hide others; later changes go to v2. |
| No containers | Docker Desktop is often restricted on work laptops. |
| Public repository | `.gitignore`, GitHub push protection and the key-prefix check guard the keys. |

## Milestones

**Milestone 1: VirusTotal end to end.** Branch `milestone-1`, one pull request. Done when:
- `GET /api/v1/hash/{hash}` returns the VirusTotal result in the contract shape; an invalid hash gets the 400 body
- The Streamlit page shows the result; README explains install and run on Windows
- `git log -p | findstr /i "<first 6 chars of your key>"` finds nothing, for each key
- Merged through a pull request

**Milestone 2: three sources and tests.** Branch `milestone-2`, one pull request. Done when:
- All three sources return a result; a failing source still shows the other two, with its error on the page
- Tests run with the network off and cover a hit, an unknown hash and a source error
- design.md and README match the code

## Environment

Windows, developed on Python 3.14 (3.12+ supported). Versions from PyPI on 5 Nov 2026; re-check when pinning `requirements.txt`:
`fastapi==0.162.0`, `uvicorn==0.54.0`, `streamlit==1.66.1`, `httpx==0.28.1`, `pytest==9.2.0`, `python-dotenv==1.2.4`.
All install on Windows with 3.14 (httpx officially lists only up to 3.12 and hasn't released since Dec 2024, but is pure Python).

## Open questions

- MalwareBazaar `get_info`: does it accept SHA-1? What are the success and bad-key responses? Confirm by recording.
- ThreatFox `search_hash`: "not found" and bad-key `query_status` values are undocumented. Confirm by recording.
- VirusTotal: docs don't say whether hash lookups are visible to others. Treat them as not private.
- VirusTotal GUI link format is not in the API docs. Check it once by hand.
