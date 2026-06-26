"""
API Key Manager
---------------
Keys are stored in Redis as hashes under  apikey:{sha256(key)}
so the plaintext never persists beyond the creation response.

Schema per key:
  key_id       – short human-readable identifier  (e.g. "key_a1b2c3")
  name         – caller-supplied label             (e.g. "mobile-app")
  hashed_key   – SHA-256 hex of the raw key
  role         – "user" | "admin"
  rate_limit   – per-minute request limit (overrides global default)
  created_at   – ISO-8601 timestamp
  last_used_at – ISO-8601 timestamp (updated on every auth)
  is_active    – "1" | "0"
  usage_count  – cumulative request count
"""

import hashlib
import hmac
import logging
import secrets
import json
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_PREFIX = "apikey:"
_INDEX_KEY = "apikey:index"          # Redis Set — all key_ids
_KEY_LENGTH = 32                      # bytes → 64-char hex token


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _redis_key(hashed: str) -> str:
    return f"{_PREFIX}{hashed}"


class APIKeyManager:
    def __init__(self, redis_client):
        self._r = redis_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_key(
        self,
        name: str,
        role: str = "user",
        rate_limit: int = 60,
    ) -> dict:
        """
        Generate a new API key.  Returns the record INCLUDING the plaintext
        key — this is the only time the plaintext is available.
        """
        if role not in ("user", "admin"):
            raise ValueError(f"Invalid role '{role}'. Must be 'user' or 'admin'.")

        raw_key = f"sentri_{secrets.token_hex(_KEY_LENGTH)}"
        hashed = _hash(raw_key)
        key_id = f"key_{secrets.token_hex(3)}"

        record = {
            "key_id": key_id,
            "name": name,
            "hashed_key": hashed,
            "role": role,
            "rate_limit": str(rate_limit),
            "created_at": _now(),
            "last_used_at": "",
            "is_active": "1",
            "usage_count": "0",
        }

        pipe = self._r.pipeline()
        pipe.hset(_redis_key(hashed), mapping=record)
        pipe.sadd(_INDEX_KEY, key_id)
        # secondary index: key_id → hashed_key  (for revoke-by-id)
        pipe.set(f"apikey:id:{key_id}", hashed)
        pipe.execute()

        logger.info(f"API key created: {key_id} name='{name}' role={role}")
        return {**record, "api_key": raw_key, "rate_limit": rate_limit}

    def validate(self, raw_key: str) -> Optional[dict]:
        """
        Validate a key.  Returns the key record (without plaintext) or None.
        Bumps last_used_at and usage_count on success.
        """
        hashed = _hash(raw_key)
        rkey = _redis_key(hashed)
        record = self._r.hgetall(rkey)

        if not record:
            return None
        if record.get("is_active") != "1":
            return None

        # Update usage stats (fire-and-forget style — don't block on it)
        try:
            pipe = self._r.pipeline()
            pipe.hset(rkey, "last_used_at", _now())
            pipe.hincrby(rkey, "usage_count", 1)
            pipe.execute()
        except Exception as e:
            logger.warning(f"Could not update key usage stats: {e}")

        return {
            "key_id": record["key_id"],
            "name": record["name"],
            "role": record["role"],
            "rate_limit": int(record.get("rate_limit", 60)),
            "usage_count": int(record.get("usage_count", 0)),
        }

    def revoke(self, key_id: str) -> bool:
        """Soft-delete: mark is_active=0.  Key record is kept for audit."""
        hashed = self._r.get(f"apikey:id:{key_id}")
        if not hashed:
            return False
        updated = self._r.hset(_redis_key(hashed), "is_active", "0")
        logger.info(f"API key revoked: {key_id}")
        return True

    def rotate(self, key_id: str) -> Optional[dict]:
        """
        Issue a new raw key for the same key_id/name/role.
        Old key is revoked atomically.
        """
        hashed = self._r.get(f"apikey:id:{key_id}")
        if not hashed:
            return None

        old_record = self._r.hgetall(_redis_key(hashed))
        if not old_record:
            return None

        # Revoke old key
        self._r.hset(_redis_key(hashed), "is_active", "0")

        # Create replacement with same metadata
        return self.create_key(
            name=old_record["name"],
            role=old_record["role"],
            rate_limit=int(old_record.get("rate_limit", 60)),
        )

    def list_keys(self) -> list[dict]:
        """Return all key records (no plaintext)."""
        key_ids = self._r.smembers(_INDEX_KEY)
        results = []
        for kid in key_ids:
            hashed = self._r.get(f"apikey:id:{kid}")
            if not hashed:
                continue
            record = self._r.hgetall(_redis_key(hashed))
            if record:
                results.append({
                    "key_id": record["key_id"],
                    "name": record["name"],
                    "role": record["role"],
                    "rate_limit": int(record.get("rate_limit", 60)),
                    "created_at": record.get("created_at"),
                    "last_used_at": record.get("last_used_at") or None,
                    "is_active": record.get("is_active") == "1",
                    "usage_count": int(record.get("usage_count", 0)),
                })
        return sorted(results, key=lambda r: r["created_at"], reverse=True)

    def get_key(self, key_id: str) -> Optional[dict]:
        hashed = self._r.get(f"apikey:id:{key_id}")
        if not hashed:
            return None
        record = self._r.hgetall(_redis_key(hashed))
        if not record:
            return None
        return {
            "key_id": record["key_id"],
            "name": record["name"],
            "role": record["role"],
            "rate_limit": int(record.get("rate_limit", 60)),
            "created_at": record.get("created_at"),
            "last_used_at": record.get("last_used_at") or None,
            "is_active": record.get("is_active") == "1",
            "usage_count": int(record.get("usage_count", 0)),
        }

    def seed_admin_key(self, raw_key: str) -> bool:
        """
        Register a pre-defined admin key from .env (GATEWAY_ADMIN_KEY).
        No-ops if the key already exists.  Returns True if newly created.
        """
        hashed = _hash(raw_key)
        if self._r.exists(_redis_key(hashed)):
            return False
        self.create_key(name="admin-bootstrap", role="admin", rate_limit=1000)
        # Overwrite with deterministic key instead of random one
        key_ids = self._r.smembers(_INDEX_KEY)
        # find our just-created record and overwrite the stored hash
        # simpler: just store directly
        key_id = f"key_admin"
        record = {
            "key_id": key_id,
            "name": "admin-bootstrap",
            "hashed_key": hashed,
            "role": "admin",
            "rate_limit": "1000",
            "created_at": _now(),
            "last_used_at": "",
            "is_active": "1",
            "usage_count": "0",
        }
        pipe = self._r.pipeline()
        pipe.hset(_redis_key(hashed), mapping=record)
        pipe.sadd(_INDEX_KEY, key_id)
        pipe.set(f"apikey:id:{key_id}", hashed)
        pipe.execute()
        logger.info("Admin bootstrap key registered from environment")
        return True


# Singleton — injected with Redis client at startup
key_manager: Optional[APIKeyManager] = None


def init_key_manager(redis_client) -> APIKeyManager:
    global key_manager
    key_manager = APIKeyManager(redis_client)
    return key_manager


def get_key_manager() -> APIKeyManager:
    if key_manager is None:
        raise RuntimeError("KeyManager not initialised — call init_key_manager() at startup")
    return key_manager
