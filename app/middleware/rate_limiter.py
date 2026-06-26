"""
Sliding-window rate limiter backed by Redis.

Priority order for the rate limit ceiling:
  1. Per-key limit stored on the API key record (set at key creation)
  2. Global default from settings

The key_id is extracted from the request state (set by the auth dependency
after key validation). For unauthenticated paths, falls back to IP.
"""
import time
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

_RATE_LIMITED_PATHS = {"/v1/chat"}
_DEFAULT_LIMIT = 60
_DEFAULT_WINDOW = 60


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_client, limit: int = _DEFAULT_LIMIT, window: int = _DEFAULT_WINDOW):
        super().__init__(app)
        self.redis = redis_client
        self.default_limit = limit
        self.window = window

    def _client_key(self, request: Request) -> tuple[str, int]:
        """
        Returns (redis_rate_key, effective_limit).
        Uses key_id from request state if auth has already run (it hasn't
        in middleware — so we use IP here and per-key enforcement is done
        in the auth dependency layer).
        """
        forwarded = request.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            request.client.host if request.client else "unknown"
        )
        # Check for per-key limit hint injected by a previous middleware pass
        per_key_limit = getattr(request.state, "rate_limit", None)
        key_id = getattr(request.state, "key_id", None)

        if key_id:
            return f"rl:key:{key_id}", per_key_limit or self.default_limit
        return f"rl:ip:{ip}", self.default_limit

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path not in _RATE_LIMITED_PATHS:
            return await call_next(request)

        redis_key, limit = self._client_key(request)
        now = time.time()
        window_start = now - self.window

        try:
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zcard(redis_key)
            pipe.zadd(redis_key, {str(now): now})
            pipe.expire(redis_key, self.window * 2)
            results = pipe.execute()

            count_before = results[1]
            remaining = max(0, limit - count_before - 1)
            reset_at = int(now) + self.window

            if count_before >= limit:
                logger.warning(f"Rate limit exceeded: {redis_key}")
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "limit": limit,
                        "window_seconds": self.window,
                        "retry_after": self.window,
                    },
                    headers={
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset_at),
                        "Retry-After": str(self.window),
                    },
                )
        except Exception as e:
            logger.error(f"Rate limiter error: {e} — failing open")
            return await call_next(request)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response
