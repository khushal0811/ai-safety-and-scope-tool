"""FastAPI application entry point for AI Safety & Scope Tool (SST).

Zero Host Execution: SST is strictly a static analysis and verification engine.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import roe_router, audit_router, normalize_router
from app.config import settings
from app.engine.cve_validator import load_cve_database

app = FastAPI(
    title="AI Safety & Scope Tool (SST) API",
    description="Deterministic verification engine for LLM cybersecurity recommendations.",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(roe_router)
app.include_router(audit_router)
app.include_router(normalize_router)


@app.get("/")
async def root():
    """Service status and engine metadata."""
    return {
        "service": "AI Safety & Scope Tool (SST)",
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
