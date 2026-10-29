"""FastAPI application entry point for Vallum (AI Safety & Scope Boundary Engine).

Zero Host Execution: Vallum is strictly a static analysis and verification engine.
"""

from collections import defaultdict, deque
import os
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import roe_router, audit_router, normalize_router, benchmark_router, vault_router, sandbox_router
from app.config import settings
from app.engine.cve_validator import load_cve_database

app = FastAPI(
    title="Vallum — AI Safety & Scope Engine API",
    description="Deterministic verification engine for LLM cybersecurity recommendations.",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

if settings.ENVIRONMENT not in ("development", "staging", "production"):
    raise RuntimeError(f"Unrecognized ENVIRONMENT='{settings.ENVIRONMENT}' — refusing to start.")

# CORS middleware configuration — scoped to official Vallum Vercel deployments + configured origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://(vallum|ai-safety-and-scope-tool)(-[a-z0-9-]+)?\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sliding-window rate limiter (protects LLM-consuming and public endpoints from abuse)
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_LLM_HEAVY_PREFIXES = ("/api/roe/parse", "/api/benchmark/query", "/api/benchmark/evaluate")


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if os.getenv("PYTEST_CURRENT_TEST"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    is_heavy = any(path.startswith(p) for p in _LLM_HEAVY_PREFIXES)
    bucket_key = f"{client_ip}:{'heavy' if is_heavy else 'general'}"
    max_requests = 30 if is_heavy else 120
    window_sec = 60.0

    now = time.monotonic()
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
    """System health check and database telemetry."""
    cve_db = load_cve_database()
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "engine": "deterministic_v2",
        "cached_cves": len(cve_db),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )
