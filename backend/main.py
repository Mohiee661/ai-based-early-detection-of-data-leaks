"""FastAPI service entry point for the DarkShield backend."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from api.routes.alerts import router as alerts_router
from api.routes.cases import router as cases_router
from api.routes.investigations import router as investigations_router
from api.routes.copilot import router as copilot_router
from api.routes.auth import router as auth_router
from api.routes.analytics import router as analytics_router
from api.routes.findings import router as findings_router
from api.routes.lookup import router as lookup_router
from app.ai.device import log_device_status
from api.schemas.findings import HealthResponse
from api.services.alerts_service import alert_service
from api.services.findings_service import FindingsService
from core.config import get_settings


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
settings = get_settings()
service = FindingsService()
log_device_status()

app = FastAPI(
    title="DarkShield Backend",
    version="1.0.0",
    description="Render-ready API for DarkShield findings and health endpoints.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(findings_router)
app.include_router(lookup_router)
app.include_router(analytics_router)
app.include_router(alerts_router)
app.include_router(cases_router)
app.include_router(investigations_router)
app.include_router(auth_router)
app.include_router(copilot_router)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "DarkShield Backend",
        "status": "ok",
        "health": "/health",
        "findings": "/api/findings",
        "metrics": "/api/dashboard/metrics",
        "lookup": "/api/lookup",
        "analytics": "/api/analytics/summary",
        "timeline": "/api/investigations/timeline",
        "cases": "/api/cases",
        "copilot": "/api/copilot/chat",
        "copilot_stream": "/api/copilot/chat/stream",
    }


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    database_connected = await service.health_check()
    return HealthResponse(
        status="ok" if database_connected else "degraded",
        database_connected=database_connected,
        checked_at=datetime.now(timezone.utc),
    )


@app.get("/healthz", response_model=HealthResponse, include_in_schema=False)
async def healthz() -> HealthResponse:
    return await health()


@app.on_event("startup")
async def sync_alerts_on_startup() -> None:
    try:
        await alert_service.sync_missing_alerts()
    except Exception as exc:
        LOGGER.exception("Alert backfill on startup failed: %s", exc)
