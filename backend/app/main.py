"""FastAPI application entry point for Vallum (AI Safety & Scope Boundary Engine).

Zero Host Execution: Vallum is strictly a static analysis and verification engine.
"""

from collections import defaultdict, deque
import os
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from app.api import roe_router, audit_router, normalize_router, benchmark_router, vault_router, sandbox_router
from app.config import settings
from app.engine.cve_validator import load_cve_database
from app.engine.daemon_auth import SIGNATURE_HEADER, sign_body

app = FastAPI(
    title="Vallum — AI Safety & Scope Engine API",
    description="Deterministic verification engine for LLM cybersecurity recommendations.",
    version="0.2.0",
    # Interactive API docs and the schema are a map of the deployment: not exposed in production
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
)

if settings.ENVIRONMENT not in ("development", "staging", "production"):
    raise RuntimeError(f"Unrecognized ENVIRONMENT='{settings.ENVIRONMENT}' — refusing to start.")

# CORS: exact origins only (CORS_ORIGINS). Wildcard Vercel suffixes are claimable by anyone.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sliding-window rate limiter (protects LLM-consuming and public endpoints from abuse)
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_LLM_HEAVY_PREFIXES = (
    "/api/roe/parse",
    "/api/benchmark/query",
    "/api/benchmark/evaluate",
    "/api/audit",  # AI Judge path can spend the server's LLM key
)
_sweep_counter = 0


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    global _sweep_counter
    if os.getenv("PYTEST_CURRENT_TEST"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    is_heavy = any(path.startswith(p) for p in _LLM_HEAVY_PREFIXES)
    bucket_key = f"{client_ip}:{'heavy' if is_heavy else 'general'}"
    max_requests = 30 if is_heavy else 120
    window_sec = 60.0

    now = time.monotonic()

    # Periodically drop idle buckets so rotating source addresses cannot grow memory without bound
    _sweep_counter += 1
    if _sweep_counter % 1024 == 0:
        for stale_key in [k for k, dq in _rate_buckets.items() if not dq or now - dq[-1] > window_sec]:
            del _rate_buckets[stale_key]

    q = _rate_buckets[bucket_key]
    while q and (now - q[0]) > window_sec:
        q.popleft()

    if len(q) >= max_requests:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please wait before sending more requests."},
        )
    q.append(now)
    return await call_next(request)

MAX_REQUEST_BODY_BYTES = 1_000_000


@app.middleware("http")
async def body_size_guard(request: Request, call_next):
    """Reject oversized bodies before FastAPI buffers and validates them.

    Covers requests that declare Content-Length. Chunked bodies without a length header are
    still bounded by the per-field limits on the request models.
    """
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_REQUEST_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large."})
    return await call_next(request)


DAEMON_SIGNED_PATH = "/api/audit/deterministic"


@app.middleware("http")
async def sign_daemon_audit_responses(request: Request, call_next):
    """Sign deterministic audit responses so the local CLI can verify them before acting on a verdict."""
    response = await call_next(request)
    if request.url.path.rstrip("/") != DAEMON_SIGNED_PATH:
        return response

    body = b"".join([chunk async for chunk in response.body_iterator])
    headers = dict(response.headers)
    headers.pop("content-length", None)
    headers[SIGNATURE_HEADER] = sign_body(body)
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
    )


# Mount API Routers
app.include_router(roe_router)
app.include_router(audit_router)
app.include_router(normalize_router)
app.include_router(benchmark_router)
app.include_router(vault_router)
app.include_router(sandbox_router)


@app.get("/")
async def root():
    """Service status and engine metadata."""
    return {
        "service": "Vallum — AI Safety & Scope Engine",
        "status": "online",
        "version": "0.2.0",
        "engine": "deterministic_v2",
        "zero_host_execution": True,
    }


@app.get("/api/health")
async def health_check():
    """Liveness probe. Returns a fixed payload with no deployment detail."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )
