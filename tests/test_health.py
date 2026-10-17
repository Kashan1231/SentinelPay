"""
Smoke test for the /health endpoint.
"""

from conftest import client


def test_health_returns_200() -> None:
    """GET /health should return 200 with status ok."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_response_body() -> None:
    """Response body must contain status and database keys."""
    response = client.get("/health")
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
