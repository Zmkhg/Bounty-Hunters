import json
from typing import Any

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError, WebSocketRequestValidationError
from fastapi.utils import is_body_allowed_for_status_code
from fastapi.websockets import WebSocket
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import WS_1008_POLICY_VIOLATION

SENSITIVE_FIELD_NAMES = {"password", "secret", "token", "api_key"}
REDACTED_VALUE = "***REDACTED***"


def _redact_sensitive_fields(data: Any) -> Any:
    """Recursively redact sensitive fields from a JSON-compatible object."""
    if isinstance(data, dict):
        return {
            key: REDACTED_VALUE if key.lower() in SENSITIVE_FIELD_NAMES
            else _redact_sensitive_fields(value)
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [_redact_sensitive_fields(item) for item in data]
    return data


def _safe_get_body(request: Request, debug: bool) -> Any | None:
    """Attempt to read and redact the request body, returning None if unavailable."""
    if not debug:
        return None
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return None
        body_text = body_bytes.decode("utf-8", errors="replace")
        parsed = json.loads(body_text)
        return _redact_sensitive_fields(parsed)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Non-JSON body — return as redacted string to avoid leaking raw secrets
        raw = body_bytes.decode("utf-8", errors="replace")
        sanitized = raw
        for field in SENSITIVE_FIELD_NAMES:
            sanitized = sanitized.replace(field, REDACTED_VALUE)
        return REDACTED_VALUE if len(sanitized) > 500 else sanitized
    except Exception:
        return None


async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    headers = getattr(exc, "headers", None)
    if not is_body_allowed_for_status_code(exc.status_code):
        return Response(status_code=exc.status_code, headers=headers)
    return JSONResponse(
        {"detail": exc.detail}, status_code=exc.status_code, headers=headers
    )


async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    is_debug = getattr(getattr(request, "app", None), "debug", False)
    content: dict[str, Any] = {
        "detail": jsonable_encoder(exc.errors()),
        "path": request.url.path,
        "method": request.method,
    }
    if is_debug:
        content["body"] = await _safe_get_body(request, debug=True)
    return JSONResponse(status_code=422, content=content)


async def websocket_request_validation_exception_handler(
    websocket: WebSocket, exc: WebSocketRequestValidationError
) -> None:
    await websocket.close(
        code=WS_1008_POLICY_VIOLATION, reason=jsonable_encoder(exc.errors())
    )