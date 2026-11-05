# hash-enrich

Enter a file hash (MD5, SHA-1 or SHA-256) and see what VirusTotal, MalwareBazaar and ThreatFox know about it, on one page.
The design and API contract are in [design.md](design.md).

The tool only ever sends a hash, never a file. Lookups are not private: never look up hashes of internal or private files.

## What you need

- Windows with **Python 3.12 or newer** (developed on 3.14). Check with `py --version`.
- A free **VirusTotal API key**: sign up at https://www.virustotal.com, then open your profile menu → **API key**.
- A free **abuse.ch Auth-Key** (one key covers MalwareBazaar and ThreatFox): sign in at https://auth.abuse.ch/ and copy your **Auth-Key**.

## Install (one time)

Open **Windows PowerShell** and go to the project folder:

```powershell
cd "$HOME\Desktop\hash-enrich"
```

Create a virtual environment (a private copy of Python for this project, in the `.venv` folder):

```powershell
py -3 -m venv .venv
```

Install the pinned libraries into it:

```powershell
.venv\Scripts\python -m pip install -r requirements.txt
```

Create your own settings file from the example, then open it:

```powershell
Copy-Item .env.example .env
```

```powershell
notepad .env
```

Replace `your-virustotal-key-here` and `your-abusech-key-here` with your two keys, save, and close Notepad.
`.env` is listed in `.gitignore`, so Git never uploads it. Never put a key in any other file.

All commands below use `.venv\Scripts\python` directly, so you never need to "activate" the virtual environment.

## Run

You need **two** PowerShell windows, both in the project folder.

**Window 1: backend** (the API)

```powershell
.venv\Scripts\python -m backend
```

Wait for `Uvicorn running on http://127.0.0.1:8000`. Leave this window open.
The backend only listens on 127.0.0.1, so only this laptop can reach it. Do not start it with `fastapi run`, which opens it to the whole network.

**Window 2: frontend** (the web page)

```powershell
.venv\Scripts\python -m streamlit run frontend/app.py
```

Your browser opens http://127.0.0.1:8501 (if it doesn't, open that address yourself; on the very first run, press Enter at Streamlit's "Email:" question). Paste a hash and click **Look up**.
The page also only listens on 127.0.0.1 (set in `.streamlit/config.toml`), so only this laptop can open it.

Hashes to try:
- `add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de`: a Mirai sample all three sources know (ThreatFox drops IOCs after 6 months, so it may become `not_found` there).
- `44d88612fea8a8f36de82e1278abb02f`: the public EICAR antivirus test file (VirusTotal only).

**Reading the page:** a verdict badge comes first. It says **Known malicious** when 5 or more VirusTotal engines flag the file, or when MalwareBazaar or ThreatFox lists it. It says **Suspicious** for 1–4 VirusTotal detections only, **No record in any source** when nothing matched (which is not proof the file is safe), and **Couldn't check** when every source failed. Below it, a summary card combines the key facts: family and aliases, detections, classification, reputation, ThreatFox confidence, delivery and origin, first seen, CVEs and tags. Then there is one tab per source with its full details or its error.

To stop either part, click its window and press **Ctrl+C**.

## Use the API directly

Use `curl.exe`, not `curl`: in Windows PowerShell, `curl` is a different command.

```powershell
curl.exe -i http://127.0.0.1:8000/api/v1/hash/add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de
```

- `200`: at least one source answered. Each source has its own `status`: `ok`, `not_found`, `unsupported` or `error`.
- `400`: the hash is not 32, 40 or 64 hex characters. No source was called.
- `502`: no source could answer. Each source's `error` says why (`missing_key`, `auth_failed`, `rate_limited`, `timeout`, `upstream_error`).

A failing source never hides the others: if one is down or its key is wrong, the other two still answer.

Health check: http://127.0.0.1:8000/api/v1/health. Interactive docs: http://127.0.0.1:8000/docs.

"Not found" and "0 detections" do not mean a file is safe.

## Settings (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_PORT` | `8000` | Backend port. If you change it, change `BACKEND_URL` too |
| `BACKEND_URL` | `http://127.0.0.1:8000` | Where the frontend finds the backend |
| `VT_API_KEY` | none | Your VirusTotal key |
| `ABUSECH_AUTH_KEY` | none | Your abuse.ch key, for MalwareBazaar and ThreatFox |
| `SOURCE_TIMEOUT_SECONDS` | `10` | How long to wait for each source |

To run the web page on another port, add `--server.port 8502` to the frontend command.

## Tests

```powershell
.venv\Scripts\python -m pytest -v
```

The tests need no API key and make no network calls, so they pass with Wi-Fi off:
- Found, unknown-hash and bad-key cases replay **recorded real responses** from `tests/fixtures/<source>/`.
- 429, 500 and timeout cases are simulated.
- A guard in `tests/conftest.py` fails any test that tries to reach the internet.

### Recording new responses

Only needed when a source changes its answers. This calls the real sources, so it needs both keys in `.env`:

```powershell
.venv\Scripts\python scripts\record.py find
```

```powershell
.venv\Scripts\python scripts\record.py record <the sha256 that find printed>
```

The files hold only the HTTP status and body, never request headers or keys. Before committing them, check (with the first 6 characters of each of your keys):

```powershell
git grep -n -i -E "x-apikey|auth-key|<first 6 of VT key>|<first 6 of abuse.ch key>" -- tests/fixtures
```

It must print nothing. If you record a new sample, update the hashes and expected values in `tests/conftest.py` and `tests/test_sources.py`.

## Troubleshooting

| Problem | Fix |
|---|---|
| Page says "Backend not running at …" | Start the backend in window 1 and check `BACKEND_URL` in `.env` |
| A source shows `missing_key` | Its key is empty in `.env` (`VT_API_KEY` or `ABUSECH_AUTH_KEY`). Fill it in and restart the backend |
| A source shows `auth_failed` | The key is wrong. Copy it again (VirusTotal profile, or auth.abuse.ch) and restart the backend |
| VirusTotal shows `rate_limited` | The free key allows 4 lookups a minute and 500 a day. Wait a minute |
| `py` is not recognized | Install Python from https://www.python.org/downloads/ and tick "Add python.exe to PATH" |
| `[Errno 10048]` when starting the backend | Port 8000 is in use. Set another `BACKEND_PORT` and matching `BACKEND_URL` in `.env` |

## If a key is ever committed

Revoke it at once (VirusTotal profile → API key; abuse.ch at auth.abuse.ch) and create a new one. This repository is public, so deleting the commit is not enough.
