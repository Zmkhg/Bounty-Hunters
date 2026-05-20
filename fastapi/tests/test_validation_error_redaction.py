"""
Tests for validation error handler with request context and body redaction.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


class Item(BaseModel):
    name: str
    password: str
    api_key: str | None = None
    nested: dict | None = None


app = FastAPI(debug=True)


@app.post("/items/")
async def create_item(item: Item):
    return item


@app.post("/simple/")
async def simple_endpoint(data: dict):
    return data


client = TestClient(app)


def test_validation_error_includes_path_and_method():
    """Validation error responses must include request path and HTTP method."""
    response = client.post("/items/", json={"name": 123})  # Invalid type
    assert response.status_code == 422
    data = response.json()
    assert "path" in data
    assert data["path"] == "/items/"
    assert "method" in data
    assert data["method"] == "POST"


def test_validation_error_includes_redacted_body_in_debug_mode():
    """In debug mode, the body must be included with sensitive fields redacted."""
    response = client.post(
        "/items/",
        json={"name": "test", "password": "secret123", "api_key": "key123"},
    )
    assert response.status_code == 422
    data = response.json()
    assert "body" in data
    body = data["body"]
    assert body["password"] == "***REDACTED***"
    assert body["api_key"] == "***REDACTED***"


def test_redaction_works_for_nested_objects():
    """Fields named password/secret/token/api_key must be redacted even when nested."""
    response = client.post(
        "/items/",
        json={
            "name": "test",
            "password": "secret",
            "nested": {"token": "nested_token", "other": "visible"},
        },
    )
    assert response.status_code == 422
    data = response.json()
    body = data["body"]
    assert body["password"] == "***REDACTED***"
    assert body["nested"]["token"] == "***REDACTED***"
    assert body["nested"]["other"] == "visible"


def test_non_debug_mode_excludes_body():
    """Non-debug mode responses must not include the body."""
    non_debug_app = FastAPI(debug=False)

    @non_debug_app.post("/items/")
    async def create_item(item: Item):
        return item

    non_debug_client = TestClient(non_debug_app)
    response = non_debug_client.post(
        "/items/", json={"name": "test", "password": "secret"}
    )
    assert response.status_code == 422
    data = response.json()
    assert "body" not in data
    assert "path" in data
    assert "method" in data