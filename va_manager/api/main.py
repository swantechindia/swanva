"""FastAPI application entrypoint for Swan VA."""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

from va_manager.api.deps import get_engine
from va_manager.api.router import router as va_router
from va_manager.config import (
    SSL_CERT_PATH,
    SSL_KEY_PATH,
    VA_BACKEND_HOST,
    VA_BACKEND_PORT,
)
from va_manager.models import Base

app = FastAPI(title="Swan VA API", version="0.1.0")
app.add_middleware(HTTPSRedirectMiddleware)
app.include_router(va_router)


@app.on_event("startup")
def initialize_database() -> None:
    """Ensure the configured database schema exists before serving requests."""

    Base.metadata.create_all(bind=get_engine())


def get_tls_uvicorn_kwargs() -> dict[str, object]:
    """Return host, port, and TLS-related Uvicorn keyword arguments from config."""

    return {
        "host": VA_BACKEND_HOST,
        "port": VA_BACKEND_PORT,
        "ssl_certfile": SSL_CERT_PATH,
        "ssl_keyfile": SSL_KEY_PATH,
    }


if __name__ == "__main__":
    uvicorn.run("va_manager.api.main:app", **get_tls_uvicorn_kwargs())
