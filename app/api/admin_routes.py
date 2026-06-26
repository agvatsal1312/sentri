"""
Admin API for API key management.
All endpoints require an admin-role key.

POST   /admin/keys              — create a new key
GET    /admin/keys              — list all keys (no plaintext)
GET    /admin/keys/{key_id}     — inspect one key
DELETE /admin/keys/{key_id}     — revoke a key
POST   /admin/keys/{key_id}/rotate — rotate (replace) a key
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.auth.dependencies import require_admin, KeyRecord
from app.auth.key_manager import get_key_manager

logger = logging.getLogger(__name__)
admin_router = APIRouter(prefix="/admin", tags=["Admin"])


# ------------------------------------------------------------------
# Request / response schemas
# ------------------------------------------------------------------

class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80, description="Human-readable label for this key")
    role: str = Field(default="user", description="'user' or 'admin'")
    rate_limit: int = Field(default=60, ge=1, le=10_000, description="Max requests per minute for this key")


class CreateKeyResponse(BaseModel):
    api_key: str           # plaintext — shown ONCE
    key_id: str
    name: str
    role: str
    rate_limit: int
    created_at: str
    message: str = "Store this key securely — it will not be shown again."


class KeySummary(BaseModel):
    key_id: str
    name: str
    role: str
    rate_limit: int
    created_at: str
    last_used_at: Optional[str]
    is_active: bool
    usage_count: int


class RevokeResponse(BaseModel):
    key_id: str
    revoked: bool
    message: str


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@admin_router.post("/keys", response_model=CreateKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: CreateKeyRequest,
    caller: KeyRecord = Depends(require_admin),
):
    """Create a new API key. Returns the plaintext key once."""
    km = get_key_manager()
    try:
        record = km.create_key(name=body.name, role=body.role, rate_limit=body.rate_limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"error": str(e)})

    logger.info(f"Key created by admin '{caller.name}': {record['key_id']} role={body.role}")
    return CreateKeyResponse(
        api_key=record["api_key"],
        key_id=record["key_id"],
        name=record["name"],
        role=record["role"],
        rate_limit=record["rate_limit"],
        created_at=record["created_at"],
    )


@admin_router.get("/keys", response_model=list[KeySummary])
async def list_keys(caller: KeyRecord = Depends(require_admin)):
    """List all keys with metadata. Plaintext keys are never returned."""
    km = get_key_manager()
    return km.list_keys()


@admin_router.get("/keys/{key_id}", response_model=KeySummary)
async def get_key(key_id: str, caller: KeyRecord = Depends(require_admin)):
    """Inspect a single key by its ID."""
    km = get_key_manager()
    record = km.get_key(key_id)
    if not record:
        raise HTTPException(status_code=404, detail={"error": f"Key '{key_id}' not found"})
    return record


@admin_router.delete("/keys/{key_id}", response_model=RevokeResponse)
async def revoke_key(key_id: str, caller: KeyRecord = Depends(require_admin)):
    """
    Revoke a key immediately. The key is soft-deleted (record kept for audit).
    Any in-flight requests using the key will fail on their next auth check.
    """
    km = get_key_manager()
    ok = km.revoke(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail={"error": f"Key '{key_id}' not found"})

    logger.info(f"Key {key_id} revoked by admin '{caller.name}'")
    return RevokeResponse(
        key_id=key_id,
        revoked=True,
        message=f"Key '{key_id}' has been revoked and will be rejected immediately.",
    )


@admin_router.post("/keys/{key_id}/rotate", response_model=CreateKeyResponse)
async def rotate_key(key_id: str, caller: KeyRecord = Depends(require_admin)):
    """
    Rotate a key: revoke the old key and issue a replacement with the same
    name/role/rate_limit. Returns the new plaintext key once.
    """
    km = get_key_manager()
    record = km.rotate(key_id)
    if not record:
        raise HTTPException(status_code=404, detail={"error": f"Key '{key_id}' not found"})

    logger.info(f"Key {key_id} rotated by admin '{caller.name}' → new key {record['key_id']}")
    return CreateKeyResponse(
        api_key=record["api_key"],
        key_id=record["key_id"],
        name=record["name"],
        role=record["role"],
        rate_limit=record["rate_limit"],
        created_at=record["created_at"],
        message="Old key revoked. Store this new key securely — it will not be shown again.",
    )
