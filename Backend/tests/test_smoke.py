"""Lightweight Smoke Test Suite for Tripwire Runtime Security Harness (Phase A13).

Verifies that a fresh checkout can initialize and execute with zero external services.
"""

from fastapi.testclient import TestClient
import pytest

from app.db.models import PrincipalModel
from app.db.seed import DEMO_PRINCIPALS, seed_demo_data
from app.db.session import init_db
from app.main import app


@pytest.fixture
def smoke_client():
    """Fixture providing TestClient for smoke testing."""
    init_db()
    with TestClient(app) as client:
        yield client


class TestTripwireSmoke:
    """Smoke tests for fresh checkout readiness."""

    def test_health_check_endpoint(self, smoke_client):
        """GET /health returns 200 OK and status ok."""
        response = smoke_client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_openapi_documentation_available(self, smoke_client):
        """GET /openapi.json returns valid schema documenting all core Tripwire endpoints."""
        response = smoke_client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "paths" in schema
        paths = schema["paths"]

        # Verify all contract endpoints are present
        assert "/api/v1/sessions" in paths
        assert "/api/v1/actions/propose" in paths
        assert "/api/v1/actions/{action_id}/confirm" in paths
        assert "/api/v1/sessions/{session_id}/trajectory" in paths
        assert "/api/v1/audit/{session_id}" in paths

    def test_cors_headers_enabled(self, smoke_client):
        """CORS headers are present to support frontend connections."""
        response = smoke_client.options(
            "/api/v1/sessions",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") in ["*", "http://localhost:3000"]

    def test_deterministic_demo_seeding(self, db_session):
        """seed_demo_data seeds demo principals deterministically and idempotently."""
        seeded = seed_demo_data(db_session)
        assert len(seeded) == len(DEMO_PRINCIPALS)
        assert "fin_agent_user" in seeded
        assert "attacker_user" in seeded
        assert "user_high_risk" in seeded

        # Idempotent re-run
        seeded_again = seed_demo_data(db_session)
        assert len(seeded_again) == len(DEMO_PRINCIPALS)

        fin = db_session.query(PrincipalModel).filter(PrincipalModel.id == "fin_agent_user").first()
        assert fin is not None
        assert "customer:write" in fin.scope
