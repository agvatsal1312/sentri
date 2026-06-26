import numpy as np
import json
import hashlib
import asyncio
import logging
from sentence_transformers import SentenceTransformer
from redis import Redis
from app.core.config import settings

logger = logging.getLogger(__name__)


class SemanticCache:
    def __init__(self):
        self.redis = Redis.from_url(settings.redis_url, decode_responses=False)
        self.redis_text = Redis.from_url(settings.redis_url, decode_responses=True)
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.threshold = settings.similarity_threshold
        self.ttl = settings.cache_ttl
        # In-flight request locks: key → asyncio.Event
        # Prevents cache stampede: multiple concurrent misses for the same query
        self._inflight: dict[str, asyncio.Event] = {}
        self._ensure_index()

    # ------------------------------------------------------------------
    # Exact (L1) cache
    # ------------------------------------------------------------------
    def get_exact(self, query: str) -> dict | None:
        key = f"exact:{hashlib.md5(query.encode()).hexdigest()}"
        response = self.redis_text.get(key)
        if response:
            return {
                "response": response,
                "cached_query": query,
                "similarity": 1.0,
                "cache_hit": True,
                "cache_type": "exact",
            }
        return None

    def set_exact(self, query: str, response: str) -> None:
        key = f"exact:{hashlib.md5(query.encode()).hexdigest()}"
        self.redis_text.set(key, response, ex=self.ttl)

    # ------------------------------------------------------------------
    # Semantic (L2) cache  — with stampede guard
    # ------------------------------------------------------------------
    async def get_or_lock(self, query: str) -> tuple[dict | None, bool]:
        """
        Check semantic cache.  Returns (cached_result | None, acquired_lock).
        If acquired_lock is True, the caller won the race and must call
        release_lock() after populating the cache.
        If cached_result is None and acquired_lock is False, wait for the
        in-flight request to finish and retry once.
        """
        cache_key = hashlib.md5(query.encode()).hexdigest()

        # Fast path: already cached
        result = self.get(query)
        if result:
            return result, False

        # Stampede guard: check if another coroutine is already working on this
        if cache_key in self._inflight:
            event = self._inflight[cache_key]
            logger.debug(f"Waiting for in-flight request: {cache_key[:8]}")
            try:
                await asyncio.wait_for(asyncio.shield(event.wait()), timeout=10.0)
            except asyncio.TimeoutError:
                pass
            # Re-check cache after waiting
            result = self.get_exact(query) or self.get(query)
            return result, False

        # We won the race — register our lock
        event = asyncio.Event()
        self._inflight[cache_key] = event
        return None, True

    def release_lock(self, query: str):
        """Signal waiting coroutines that the cache has been populated."""
        cache_key = hashlib.md5(query.encode()).hexdigest()
        event = self._inflight.pop(cache_key, None)
        if event:
            event.set()

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------
    def _ensure_index(self):
        try:
            self.redis_text.execute_command("FT.INFO", "cache_index")
            logger.info("Cache index already exists")
        except Exception:
            self.redis_text.execute_command(
                "FT.CREATE", "cache_index",
                "ON", "HASH",
                "PREFIX", "1", "cache:",
                "SCHEMA",
                "embedding", "VECTOR", "FLAT", "6",
                "TYPE", "FLOAT32",
                "DIM", "384",
                "DISTANCE_METRIC", "COSINE",
                "query", "TEXT",
                "response", "TEXT",
            )
            logger.info("Cache index created")

    # ------------------------------------------------------------------
    # Embedding helpers
    # ------------------------------------------------------------------
    def _embed(self, text: str) -> np.ndarray:
        return self.model.encode(text, normalize_embeddings=True)

    def _vec_to_bytes(self, vec: np.ndarray) -> bytes:
        return vec.astype(np.float32).tobytes()

    # ------------------------------------------------------------------
    # Semantic lookup (sync — called inside async context via normal await)
    # ------------------------------------------------------------------
    def get(self, query: str) -> dict | None:
        embedding = self._embed(query)
        vec_bytes = self._vec_to_bytes(embedding)

        try:
            results = self.redis.execute_command(
                "FT.SEARCH", "cache_index",
                "*=>[KNN 1 @embedding $vec AS score]",
                "PARAMS", "2", "vec", vec_bytes,
                "SORTBY", "score",
                "RETURN", "3", "query", "response", "score",
                "DIALECT", "2",
            )

            if results[0] == 0:
                return None

            fields = results[2]
            field_dict = {}
            for i in range(0, len(fields), 2):
                k = fields[i].decode() if isinstance(fields[i], bytes) else fields[i]
                v = fields[i + 1].decode() if isinstance(fields[i + 1], bytes) else fields[i + 1]
                field_dict[k] = v

            score = float(field_dict.get("score", 1.0))
            similarity = 1 - score

            if similarity >= self.threshold:
                return {
                    "response": field_dict.get("response"),
                    "cached_query": field_dict.get("query"),
                    "similarity": round(similarity, 4),
                    "cache_hit": True,
                    "cache_type": "semantic",
                }
        except Exception as e:
            logger.error(f"Cache lookup error: {e}")

        return None

    def set(self, query: str, response: str) -> None:
        embedding = self._embed(query)
        vec_bytes = self._vec_to_bytes(embedding)
        key = f"cache:{hashlib.md5(query.encode()).hexdigest()}"

        self.redis.hset(key, mapping={
            b"query": query.encode(),
            b"response": response.encode(),
            b"embedding": vec_bytes,
        })
        self.redis.expire(key, self.ttl)
        self.set_exact(query, response)

    def invalidate(self, query: str) -> bool:
        key = f"cache:{hashlib.md5(query.encode()).hexdigest()}"
        exact_key = f"exact:{hashlib.md5(query.encode()).hexdigest()}"
        deleted = self.redis_text.delete(key, exact_key)
        return bool(deleted)

    def flush(self) -> None:
        keys = self.redis_text.keys("cache:*") + self.redis_text.keys("exact:*")
        if keys:
            self.redis_text.delete(*keys)


# singleton
semantic_cache = SemanticCache()
