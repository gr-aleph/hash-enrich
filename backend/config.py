"""Settings read from environment variables (loaded from .env). See design.md, Configuration."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Values already set in the environment win over .env.
load_dotenv()

# Fixed on purpose: the backend has no login, so it must only be reachable from this laptop.
BACKEND_HOST = "127.0.0.1"


@dataclass(frozen=True)
class Settings:
    backend_port: int
    vt_api_key: str
    source_timeout_seconds: float
    # One abuse.ch key covers MalwareBazaar and ThreatFox.
    abusech_auth_key: str = ""


def get_settings() -> Settings:
    return Settings(
        backend_port=int(os.getenv("BACKEND_PORT", "8000")),
        vt_api_key=os.getenv("VT_API_KEY", "").strip(),
        source_timeout_seconds=float(os.getenv("SOURCE_TIMEOUT_SECONDS", "10")),
        abusech_auth_key=os.getenv("ABUSECH_AUTH_KEY", "").strip(),
    )
