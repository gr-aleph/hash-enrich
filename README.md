# hash-enrich

Enter a file hash (MD5, SHA-1 or SHA-256) and see what threat-intelligence sources know about it, on one page.
Milestone 1 covers VirusTotal. The design and API contract are in [design.md](design.md).

The tool only ever sends a hash, never a file. Lookups are not private: never look up hashes of internal or private files.

## What you need

- Windows with **Python 3.12 or newer** (developed on 3.14). Check with `py --version`.
- A free **VirusTotal API key**: sign up at https://www.virustotal.com, then open your profile menu → **API key**.

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

Replace `your-virustotal-key-here` with your key, save, and close Notepad.
`.env` is listed in `.gitignore`, so Git never uploads it. Never put your key in any other file.

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

Your browser opens http://127.0.0.1:8501. Paste a hash and click **Look up**.
The page also only listens on 127.0.0.1 (set in `.streamlit/config.toml`), so only this laptop can open it.
To try it safely, use the public EICAR antivirus test file: `44d88612fea8a8f36de82e1278abb02f`.

To stop either part, click its window and press **Ctrl+C**.

## Use the API directly

Use `curl.exe`, not `curl`: in Windows PowerShell, `curl` is a different command.

```powershell
curl.exe -i http://127.0.0.1:8000/api/v1/hash/44d88612fea8a8f36de82e1278abb02f
```

- `200`: at least one source answered. Each source has its own `status`: `ok`, `not_found`, `unsupported` or `error`.
- `400`: the hash is not 32, 40 or 64 hex characters. No source was called.
- `502`: no source could answer. Each source's `error` says why (`missing_key`, `auth_failed`, `rate_limited`, `timeout`, `upstream_error`).

Health check: http://127.0.0.1:8000/api/v1/health. Interactive docs: http://127.0.0.1:8000/docs.

"Not found" and "0 detections" do not mean a file is safe.

## Settings (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_PORT` | `8000` | Backend port. If you change it, change `BACKEND_URL` too |
| `BACKEND_URL` | `http://127.0.0.1:8000` | Where the frontend finds the backend |
| `VT_API_KEY` | none | Your VirusTotal key |
| `ABUSECH_AUTH_KEY` | none | abuse.ch key (used from Milestone 2) |
| `SOURCE_TIMEOUT_SECONDS` | `10` | How long to wait for each source |

To run the web page on another port, add `--server.port 8502` to the frontend command.

## Tests

```powershell
.venv\Scripts\python -m pytest
```

The tests make no network calls and need no API key; VirusTotal is simulated.

## Troubleshooting

| Problem | Fix |
|---|---|
| Page says "Backend not running at …" | Start the backend in window 1 and check `BACKEND_URL` in `.env` |
| VirusTotal shows `missing_key` | `VT_API_KEY` is empty in `.env`. Fill it in and restart the backend |
| VirusTotal shows `auth_failed` | The key is wrong. Copy it again from your VirusTotal profile and restart the backend |
| VirusTotal shows `rate_limited` | The free key allows 4 lookups a minute and 500 a day. Wait a minute |
| `py` is not recognized | Install Python from https://www.python.org/downloads/ and tick "Add python.exe to PATH" |
| `[Errno 10048]` when starting the backend | Port 8000 is in use. Set another `BACKEND_PORT` and matching `BACKEND_URL` in `.env` |

## If a key is ever committed

Revoke it at once (VirusTotal profile → API key) and create a new one. This repository is public, so deleting the commit is not enough.
