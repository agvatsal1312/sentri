"""
Metrics store with Redis-backed persistence.
Survives process restarts; flushes to Redis every N requests.
"""
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)

_REDIS_KEY = "gateway:metrics"
_FLUSH_EVERY = 10  # persist to Redis every N requests


@dataclass
class MetricsStore:
    total_requests: int = 0
    cache_hits_exact: int = 0
    cache_hits_semantic: int = 0
    cache_misses: int = 0
    blocked_injection: int = 0
    blocked_domain: int = 0
    blocked_pii_scrubbed: int = 0
    blocked_size: int = 0
    rate_limited: int = 0
    total_tokens_used: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    # Keep only the last 1000 latencies to cap memory
    _MAX_LATENCIES: int = field(default=1000, init=False, repr=False)
    _requests_since_flush: int = field(default=0, init=False, repr=False)
    _redis: Any = field(default=None, init=False, repr=False)

    def set_redis(self, redis_client):
        """Inject the Redis client and restore any persisted metrics."""
        self._redis = redis_client
        self._load()

    def _load(self):
        if not self._redis:
            return
        try:
            raw = self._redis.get(_REDIS_KEY)
            if raw:
                data = json.loads(raw)
                for k, v in data.items():
                    if hasattr(self, k) and k != "latencies_ms":
                        setattr(self, k, v)
                logger.info("Metrics restored from Redis")
        except Exception as e:
            logger.warning(f"Could not restore metrics: {e}")

    def _flush(self):
        if not self._redis:
            return
        try:
            snapshot = {
                k: v for k, v in asdict(self).items()
                if k not in ("latencies_ms",)  # don't persist raw latencies
            }
            self._redis.set(_REDIS_KEY, json.dumps(snapshot), ex=86400 * 7)
        except Exception as e:
            logger.warning(f"Could not persist metrics: {e}")

    def record_request(
        self,
        cache_type: str | None,
        blocked: bool,
        block_reason: str | None,
        tokens: int,
        latency_ms: float,
        pii_detected: bool,
    ):
        self.total_requests += 1
        self.latencies_ms = (self.latencies_ms + [latency_ms])[-self._MAX_LATENCIES:]

        if blocked:
            reason = (block_reason or "").lower()
            if "injection" in reason:
                self.blocked_injection += 1
            elif "too large" in reason or "size" in reason:
                self.blocked_size += 1
            else:
                self.blocked_domain += 1
        else:
            if pii_detected:
                self.blocked_pii_scrubbed += 1
            if cache_type == "exact":
                self.cache_hits_exact += 1
            elif cache_type == "semantic":
                self.cache_hits_semantic += 1
            else:
                self.cache_misses += 1
                self.total_tokens_used += tokens or 0

        self._requests_since_flush += 1
        if self._requests_since_flush >= _FLUSH_EVERY:
            self._flush()
            self._requests_since_flush = 0

    def record_rate_limited(self):
        self.rate_limited += 1

    @property
    def cache_hit_rate(self) -> float:
        total_cacheable = self.cache_hits_exact + self.cache_hits_semantic + self.cache_misses
        if total_cacheable == 0:
            return 0.0
        return round((self.cache_hits_exact + self.cache_hits_semantic) / total_cacheable * 100, 2)

    @property
    def avg_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return round(sum(self.latencies_ms) / len(self.latencies_ms), 2)

    @property
    def p99_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_l = sorted(self.latencies_ms)
        idx = max(0, int(len(sorted_l) * 0.99) - 1)
        return round(sorted_l[idx], 2)

    def summary(self) -> dict:
        from app.providers.factory import circuit_status
        return {
            "total_requests": self.total_requests,
            "cache_hit_rate_percent": self.cache_hit_rate,
            "cache_hits": {
                "exact": self.cache_hits_exact,
                "semantic": self.cache_hits_semantic,
            },
            "cache_misses": self.cache_misses,
            "blocked": {
                "injection_attempts": self.blocked_injection,
                "off_topic": self.blocked_domain,
                "pii_scrubbed": self.blocked_pii_scrubbed,
                "oversized_requests": self.blocked_size,
            },
            "rate_limited": self.rate_limited,
            "tokens_used": self.total_tokens_used,
            "latency": {
                "avg_ms": self.avg_latency_ms,
                "p99_ms": self.p99_latency_ms,
            },
            "circuit_breakers": circuit_status(),
        }


# singleton
metrics = MetricsStore()
