"""Unit tests for main module."""

from src.main import app


def test_index_returns_200() -> None:
    """Index route should return 200 OK."""
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200


def test_index_body() -> None:
    """Index should return a greeting."""
    client = app.test_client()
    response = client.get("/")
    assert b"Hello" in response.data
