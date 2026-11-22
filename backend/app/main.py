"""
OrgShield AI - FastAPI Main Application Server
"""

import sys
import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure root directory is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.api.endpoints import router as api_router, get_scanner
from backend.app.database.db import init_db
from ml.inference.scanner import EmailThreatScanner


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    print("[OrgShield AI] Initializing SQLite database...")
    init_db()
    print("[OrgShield AI] Pre-loading inference models...")
    scanner = EmailThreatScanner()
    if scanner.is_loaded:
        print(f"[OrgShield AI] Models loaded successfully. Active model: {scanner.best_model_name}")
    else:
        print("[OrgShield AI] Warning: Models not found on disk. Run ML training pipeline.")
    yield
    # Shutdown
    print("[OrgShield AI] Server shutting down...")


app = FastAPI(
    title="OrgShield AI - Email Threat Discovery Platform",
    description="Unsupervised Organization-Aware Email Threat Detection, Geolocation and Forensic Intelligence",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware with strict production origins and local development support
default_origins = {
    "https://org-shield-ai.vercel.app",
    "https://orgshield-ai.vercel.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}

# Configurable environment variable support for additional comma-separated origins
cors_env = os.environ.get("CORS_ORIGINS", "").strip()
if cors_env:
    for orig in cors_env.split(","):
        cleaned = orig.strip()
        if cleaned and cleaned != "*":
            # Strip trailing slash so browser Origin headers match strictly
            default_origins.add(cleaned.rstrip("/"))

allowed_origins = sorted(list(default_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "platform": "OrgShield AI",
        "status": "operational",
        "docs_url": "/docs",
        "health_check": "/api/health"
    }


@app.get("/health", tags=["System"])
def direct_health_check():
    """Root-level health check endpoint for cloud platform probes (e.g. Render)."""
    scanner = get_scanner()
    return {
        "status": "healthy",
        "service": "OrgShield AI Threat Platform",
        "models_loaded": scanner.is_loaded,
        "active_model": scanner.best_model_name,
        "version": "1.0.0"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    is_prod = os.environ.get("APP_ENV", "development").lower() == "production"
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An error occurred processing the request." if is_prod else str(exc),
            "path": str(request.url.path)
        }
    )


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.app.main:app", host=host, port=port)
