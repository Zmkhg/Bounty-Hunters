import json
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    api_key: str


class NestedRequest(BaseModel):
    user: LoginRequest
    metadata: dict


class MixedRequest(BaseModel):
    name: str
    secret: str
    details: LoginRequest
    items: list


app = FastAPI()
client = TestClient(app)


@app.post("/login")
def login(data: LoginRequest):
    return {"status": "ok"}  # pragma: no cover


@app.post("/nested")
def nested(data: NestedRequest):
    return {"status": "ok"}  # pragma: no cover


@app.post("/mixed")
def mixed(data: MixedRequest):
    return {"status": "ok"}  # pragma: no cover


def test_validation_error_includes_path_and_method():
    """Validation error responses include request path and HTTP method."""
    app.debug = False
    response = client.post("/login", json={"username": "test"})
    assert response.status_code == 422
    data = response.json()
    assert "path" in data
    assert data["path"] == "/login"
    assert "method" in data
    assert data["method"] == "POST"


def test_validation_error_includes_redacted_body_in_debug_mode():
    """In debug mode, the received body is included with sensitive fields redacted."""
    app.debug = True
    # Sending incomplete body to trigger 422 (missing api_key)
    response = client.post("/login", json={
        "username": "admin",
        "password": "s3cr3t!",
    })
    assert response.status_code == 422
    data = response.json()
    assert "body" in data
    assert data["body"]["username"] == "admin"
    assert data["body"]["password"] == "***REDACTED***"


def test_redaction_works_for_nested_objects():
    """Redaction works for nested objects containing sensitive field names."""
    app.debug = True
    # Sending incomplete nested body (missing metadata) to trigger 422
    response = client.post("/nested", json={
        "user": {
            "username": "admin",
            "password": "secret123",
            "api_key": "abc",
        },
    })
    assert response.status_code == 422
    data = response.json()
    assert "body" in data
    body = data["body"]
    assert body["user"]["username"] == "admin"
    assert body["user"]["password"] == "***REDACTED***"
    assert body["user"]["api_key"] == "***REDACTED***"


def test_non_debug_mode_excludes_body():
    """Non-debug mode responses do not include the body."""
    app.debug = False
    # Sending incomplete body to trigger 422
    response = client.post("/login", json={
        "username": "admin",
    })
    assert response.status_code == 422
    data = response.json()
    assert "body" not in data
    assert "path" in data
    assert "method" in data


def test_redaction_with_list_of_objects():
    """Sensitive fields are redacted in lists of dicts."""
    app.debug = True
    response = client.post("/mixed", json={
        "name": "test",
        "secret": "mysecret",
        "details": {"username": "u", "password": "pw"},
        "items": [
            {"name": "a", "token": "tok1"},
            {"name": "b", "token": "tok2"}
        ]
    })
    assert response.status_code == 422
    data = response.json()
    assert "body" in data
    body = data["body"]
    assert body["name"] == "test"
    assert body["secret"] == "***REDACTED***"
    assert body["details"]["username"] == "u"
    assert body["details"]["password"] == "***REDACTED***"
    assert body["items"][0]["token"] == "***REDACTED***"
    assert body["items"][1]["token"] == "***REDACTED***"