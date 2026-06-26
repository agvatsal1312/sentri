"""
FastAPI auth dependencies.

Usage in a route:
    @router.post("/v1/chat")
    async def chat(request: ChatRequest, caller: KeyRecord = Depends(require_auth)):
        ...

Admin-only routes:
    @router.get("/admin/keys")
    async def list_keys(caller: KeyRecord = Depends(require_admin)):
        ...
"""

import logging
from dataclasses import dataclass
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.auth.key_manager import get_key_manager

logger = logging.getLogger(__name__)

_API_KEY_HEADER = APIKeyHeader(
    name="X-API-Key",
    description="Gateway API key. Obtain one from POST /admin/keys.",
    auto_error=False,          # we produce our own error message
)


@dataclass
class KeyRecord:
    key_id: str
    name: str
    role: str
    rate_limit: int
    usage_count: int


def _authenticate(raw_key: str | None) -> KeyRecord:
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Missing API key",
                "hint": "Supply your key in the X-API-Key request header.",
            },
            headers={"WWW-Authenticate": "ApiKey"},
        )

    km = get_key_manager()
    record = km.validate(raw_key)

    if record is None:
        logger.warning("Auth failed — invalid or revoked key presented")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid or revoked API key"},
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return KeyRecord(
        key_id=record["key_id"],
        name=record["name"],
        role=record["role"],
        rate_limit=record["rate_limit"],
        usage_count=record["usage_count"],
    )


async def require_auth(raw_key: str | None = Security(_API_KEY_HEADER)) -> KeyRecord:
    """Dependency: any valid key (user or admin)."""
    return _authenticate(raw_key)


async def require_admin(raw_key: str | None = Security(_API_KEY_HEADER)) -> KeyRecord:
    """Dependency: admin-role key only."""
    caller = _authenticate(raw_key)
    if caller.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Admin role required for this endpoint"},
        )
    return caller
