"""Start the backend: `.venv\\Scripts\\python -m backend`.

Always listens on 127.0.0.1. Do not start it with `fastapi run`, which listens on 0.0.0.0.
"""

import uvicorn

from backend.config import BACKEND_HOST, get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run("backend.main:app", host=BACKEND_HOST, port=settings.backend_port)


if __name__ == "__main__":
    main()
