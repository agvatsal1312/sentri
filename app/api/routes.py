import time
import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from typing import Optional

from app.core.metrics import metrics
from app.cache.semantic_cache import semantic_cache
from app.guardrails.pipeline import guardrails_pipeline
from app.providers.factory import call_with_fallback
from app.providers.base import LLMRequest
from app.auth.dependencies import require_auth, KeyRecord
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


class ChatRequest(BaseModel):
    message: str
    provider: Optional[str] = "groq"
    system_prompt: Optional[str] = None
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1024

    @field_validator("message")
    @classmethod
    def message_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("message must not be empty")
        return v


class ChatResponse(BaseModel):
    response: str
    cache_hit: bool
    cache_type: Optional[str] = None
    similarity: Optional[float] = None
    provider: Optional[str] = None
    tokens_used: Optional[int] = None
    pii_detected: list = []
    latency_ms: float


@router.post("/v1/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    http_request: Request,
    caller: KeyRecord = Depends(require_auth),   # ← auth enforced here
):
    start = time.time()

    # Expose key_id to rate limiter via request state
    http_request.state.key_id = caller.key_id
    http_request.state.rate_limit = caller.rate_limit

    # Step 1 — input guardrails
    guard_result = await guardrails_pipeline.run_input(request.message)

    if not guard_result.passed:
        metrics.record_request(
            cache_type=None, blocked=True, block_reason=guard_result.blocked_reason,
            tokens=0, latency_ms=round((time.time() - start) * 1000, 2),
            pii_detected=bool(guard_result.pii_detected),
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "Request blocked by guardrails", "reason": guard_result.blocked_reason},
        )

    clean_query = guard_result.scrubbed_text

    # Step 2 — L1 exact cache
    cached = semantic_cache.get_exact(clean_query)
    if cached:
        latency = round((time.time() - start) * 1000, 2)
        metrics.record_request(
            cache_type="exact", blocked=False, block_reason=None,
            tokens=0, latency_ms=latency, pii_detected=bool(guard_result.pii_detected),
        )
        return ChatResponse(
            response=cached["response"], cache_hit=True, cache_type="exact",
            similarity=1.0, latency_ms=latency, pii_detected=guard_result.pii_detected,
        )

    # Step 3 — L2 semantic cache with stampede guard
    cached, lock_acquired = await semantic_cache.get_or_lock(clean_query)
    if cached:
        latency = round((time.time() - start) * 1000, 2)
        metrics.record_request(
            cache_type="semantic", blocked=False, block_reason=None,
            tokens=0, latency_ms=latency, pii_detected=bool(guard_result.pii_detected),
        )
        return ChatResponse(
            response=cached["response"], cache_hit=True, cache_type="semantic",
            similarity=cached["similarity"], latency_ms=latency,
            pii_detected=guard_result.pii_detected,
        )

    # Step 4 — LLM call via circuit-breaking provider factory
    try:
        llm_response, actual_provider = await call_with_fallback(
            request.provider,
            LLMRequest(
                message=clean_query,
                system_prompt=request.system_prompt or settings.default_system_prompt,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
            ),
        )
    except RuntimeError as exc:
        logger.error(f"All providers failed: {exc}")
        if lock_acquired:
            semantic_cache.release_lock(clean_query)
        raise HTTPException(
            status_code=503,
            detail={"error": "All LLM providers are unavailable. Please retry later."},
        )

    # Step 5 — output guardrails
    clean_output, output_pii = await guardrails_pipeline.run_output(llm_response.content)

    # Step 6 — cache + release stampede lock
    semantic_cache.set(clean_query, clean_output)
    if lock_acquired:
        semantic_cache.release_lock(clean_query)

    latency = round((time.time() - start) * 1000, 2)
    all_pii = guard_result.pii_detected + output_pii
    metrics.record_request(
        cache_type=None, blocked=False, block_reason=None,
        tokens=llm_response.total_tokens, latency_ms=latency,
        pii_detected=bool(all_pii),
    )
    return ChatResponse(
        response=clean_output, cache_hit=False, cache_type=None,
        provider=actual_provider, tokens_used=llm_response.total_tokens,
        latency_ms=latency, pii_detected=all_pii,
    )


# Public endpoints — no auth needed
@router.get("/health")
def health():
    return {"status": "ok"}


# Metrics — admin auth
@router.get("/metrics", dependencies=[Depends(require_auth)])
def get_metrics(caller: KeyRecord = Depends(require_auth)):
    if caller.role != "admin":
        raise HTTPException(status_code=403, detail={"error": "Admin role required"})
    return metrics.summary()


