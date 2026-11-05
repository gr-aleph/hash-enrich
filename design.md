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
  "hash": "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de",
  "hash_type": "sha256",
  "queried_at": "2026-11-05T22:18:43Z",
  "sources": {
    "virustotal": {"status": "ok", "error": null, "data": {
      "malicious": 49, "suspicious": 0, "harmless": 0, "undetected": 15,
      "type_description": "ELF", "names": ["bin.sh", "r01km93o.exe", "w5yhz6.exe", "i.elf"],
      "first_submission_date": "2026-04-17T11:50:24Z",
      "link": "https://www.virustotal.com/gui/file/add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de",
      "threat_label": "trojan.mozi/mirai", "threat_categories": ["trojan"], "threat_names": ["mozi", "mirai", "ddos"],
      "reputation": -12, "tags": ["upx", "elf", "exploit", "cve-2017-17215"],
      "last_analysis_date": "2026-11-05T19:03:42Z", "first_seen_itw_date": "2026-04-17T12:25:16Z"}},
    "malwarebazaar": {"status": "ok", "error": null, "data": {
      "signature": "Mirai", "tags": ["elf", "Mirai"], "file_type": "elf",
      "first_seen": "2026-04-17T11:47:11Z", "last_seen": "2026-07-14T08:24:54Z",
      "delivery_method": "web_download", "origin_country": "DE"}},
    "threatfox": {"status": "ok", "error": null, "data": {"matches": [{
      "malware_printable": "Mirai", "threat_type": "payload", "confidence_level": 90,
      "first_seen": "2026-11-05T19:57:10Z", "last_seen": null, "malware_alias": "Katana", "tags": ["elf", "Mirai"],
      "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai", "reference": null}]}}
  }
}
```

(Real response for a Mirai sample, 5 Nov 2026. A failing source looks like `{"status": "error", "data": null, "error": {"code": "auth_failed", "message": "VirusTotal rejected the API key (HTTP 401, WrongCredentialsError)"}}`.)

| Field | Meaning |
|---|---|
| `status` | `ok` (found), `not_found` (no record), `unsupported` (source does not accept this hash type), `error` (lookup failed) |
| `data` | Normalized fields when `status` is `ok`, otherwise `null` |
| `error.code` | `timeout`, `rate_limited`, `auth_failed`, `upstream_error`, `missing_key` |

`not_found` is not an error. "Not found" and "0 detections" do not mean "safe".

**`data` per source**
- VirusTotal: `malicious`, `suspicious`, `harmless`, `undetected` from `last_analysis_stats` (its other 4 keys are left out on purpose); `type_description`; `names`; `first_submission_date` converted from Unix timestamp to ISO 8601 UTC; `link` built as `https://www.virustotal.com/gui/file/<data.id>` (`data.id` is the SHA-256). Threat details: `threat_label`, `threat_categories`, `threat_names` (from `popular_threat_classification`, most common first); `reputation` (community score, negative = bad); `tags` (may include CVEs); `last_analysis_date`, `first_seen_itw_date` (ISO).
- MalwareBazaar (from `data[0]`): `signature`, `tags`, `file_type`, `first_seen`, `last_seen`, `delivery_method`, `origin_country`.
- ThreatFox: `matches`, a list of `{malware_printable, threat_type, confidence_level, first_seen, last_seen, malware_alias, tags, malpedia, reference}` (`last_seen`, `malware_alias`, `reference` may be `null`).
- abuse.ch dates (`2026-04-17 11:47:11`, `2026-11-05 19:57:10 UTC`) are converted to ISO 8601 UTC.
- v1 may gain optional fields over time; callers must ignore fields they don't know. A field a source doesn't send is `null`, or `[]` for lists. Existing fields are never removed or renamed within v1.

**Status mapping** (abuse.ch values confirmed by recorded responses, 5 Nov 2026)

| Result | VirusTotal | MalwareBazaar | ThreatFox |
|---|---|---|---|
| `ok` | HTTP 200 | HTTP 200, `query_status` `ok` | HTTP 200, `query_status` `ok` |
| `not_found` | HTTP 404 `NotFoundError` | HTTP 200, `hash_not_found` | HTTP 200, `no_result` |
| `unsupported` | never | never | never (all three accept MD5, SHA-1, SHA-256; the status stays in the contract for future sources) |
| `auth_failed` | HTTP 401 | HTTP 401/403, or `unknown_auth_key` (recorded: 403) | same as MalwareBazaar |
| `rate_limited` | HTTP 429 | HTTP 429 | HTTP 429 |
| `timeout` / `missing_key` | no answer in time / key empty, no request sent | same | same |
| `upstream_error` | anything else | anything else, incl. unknown `query_status` | same as MalwareBazaar |

**400 Bad Request**: invalid input, no source called. A custom handler replaces FastAPI's default 422.

```json
{"error": {"code": "invalid_hash", "message": "Expected 32, 40 or 64 hex characters (MD5, SHA-1, SHA-256)"}}
```

**502 Bad Gateway**: no source returned `ok` or `not_found`. Same body shape as 200.

### `GET /api/v1/health`

`200 {"status": "ok"}`. FastAPI also serves docs at `/docs`; this section is the contract, so if they disagree, fix the code.

## Data sources

Checked against official docs on 5 Nov 2026: [VirusTotal](https://docs.virustotal.com/reference/file-info) ([errors](https://docs.virustotal.com/reference/errors), [limits](https://docs.virustotal.com/reference/public-vs-premium-api)), [MalwareBazaar](https://bazaar.abuse.ch/api/), [ThreatFox](https://threatfox.abuse.ch/api/), [abuse.ch keys](https://auth.abuse.ch/).

| Source | Request | Limits | Hash types | Notes |
|---|---|---|---|---|
| VirusTotal | `GET https://www.virustotal.com/api/v3/files/{hash}`, header `x-apikey` | 4/min, 500/day | MD5, SHA-1, SHA-256 | Free key; not for commercial use. **Never** call `POST /api/v3/files` (upload). |
| MalwareBazaar | `POST https://mb-api.abuse.ch/api/v1/`, form `query=get_info&hash=...`, header `Auth-Key` | Fair use | MD5, SHA-1, SHA-256 (SHA-1 confirmed by recording) | Free abuse.ch key, mandatory since 30 Jun 2025. Free under fair use; commercial use may need a paid plan. |
| ThreatFox | `POST https://threatfox-api.abuse.ch/api/v1/`, JSON `{"query": "search_ioc", "search_term": "...", "exact_match": true}`, header `Auth-Key` | Fair use | MD5, SHA-1, SHA-256 (it stores `md5_hash`, `sha1_hash`, `sha256_hash` IOCs) | Same key and terms. Finds the hash itself as an IOC. IOCs older than 6 months are not returned. |

On HTTP 429 return `rate_limited`; do not retry in a loop.

## Source rules

- API keys live only in `.env` or environment variables. Never in code, tests, recordings or commits.
- The repository is public: a committed key counts as stolen. Revoke it and create a new one; deleting the commit is not enough.
- Never upload files anywhere. Hash lookups only.
- Lookups are not private. Never look up hashes of internal or private files.
- Expect failures (timeouts, 429, source down, missing or wrong key). Each becomes that source's `error`, never a crash.

## Testing

- `pytest`, no network calls; tests must pass with the network off. A guard in `tests/conftest.py` fails any test that opens a real connection.
- Hit, unknown hash and bad key: recorded real responses in `tests/fixtures/<source>/<case>.json`, saved by `scripts/record.py` as `{"status_code", "body"}` only (no request headers, no keys). Bad-key recordings use a deliberately invalid key.
- Replay: the tests swap the backend's HTTP client for one built on `httpx.MockTransport`, which routes each request by host to the matching recorded file, so no source is ever called.
- 429, 500 and timeouts: simulated the same way. Contract shape (200, 400, 502) and "one failing source still returns the other two" are tested through FastAPI's `TestClient`.
- Before committing a fixture: `git grep -n -i -E "x-apikey|auth-key|<first 6 chars of each key>" -- tests/fixtures` finds nothing.

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
| Recorded hits, unknowns and bad keys; simulated 429/500/timeouts | Timeouts can't be recorded; real 429s waste quota. |
| ThreatFox `search_ioc` (exact), not `search_hash` | `search_hash` returns IOCs *linked to* a sample (e.g. C2 URLs) and returned `no_result` for a hash ThreatFox lists; `search_ioc` finds the hash itself. |
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

- VirusTotal: docs don't say whether hash lookups are visible to others. Treat them as not private.
- Starlette warns that its test client will move from `httpx` to `httpx2`. Tests still pass; revisit when re-pinning.

Answered (5 Nov 2026): MalwareBazaar accepts SHA-1 and both abuse.ch sources answer a bad key with HTTP 403 `unknown_auth_key` (recorded); ThreatFox not found is `no_result` (recorded); the VirusTotal GUI link opens the file page (checked by hand).
