"""Tripwire FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import actions_router, audit_router, sessions_router
from app.config import settings
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager.

    Initializes database tables on startup.
    """
    init_db()
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Tripwire — Runtime Security Harness",
        description=(
            "Model-agnostic runtime security harness for AI agents. "
            "Evaluates proposed actions against authorization, reversibility, "
            "and behavioral trajectory before permitting execution."
        ),
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Enable CORS for frontend and API clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check endpoint
    @app.get("/health", tags=["system"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "ok"}

    # Register API v1 routes
    app.include_router(sessions_router, prefix="/api/v1", tags=["sessions"])
    app.include_router(actions_router, prefix="/api/v1", tags=["actions"])
    app.include_router(audit_router, prefix="/api/v1", tags=["audit", "trajectory"])

    return app


# Application instance
app = create_app()

