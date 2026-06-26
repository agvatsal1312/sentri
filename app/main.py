"""
Sentri — Production-grade LLM Gateway
Author: Vatsal Agarwal (https://github.com/agvatsal1312)
Repository: https://github.com/agvatsal1312/sentri
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from redis import Redis

from app.api.routes import router
from app.api.admin_routes import admin_router
from app.core.config import settings
from app.core.metrics import metrics
from app.middleware.rate_limiter import RateLimiterMiddleware
from app.auth.key_manager import init_key_manager
from app.guardrails.pipeline import guardrails_pipeline, InjectionGuardrail, DomainGuardrail
from app.guardrails.domain_policy import build_domain_policy

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ────────────────────────────────────────────────────
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)

    # 1. Metrics persistence
    metrics.set_redis(redis_client)

    # 2. API key manager
    km = init_key_manager(redis_client)

    # 3. Seed admin key from env if configured
    if settings.gateway_admin_key:
        created = km.seed_admin_key(settings.gateway_admin_key)
        if created:
            logger.info("Admin bootstrap key registered from GATEWAY_ADMIN_KEY env var")
        else:
            logger.info("Admin bootstrap key already exists — skipping seed")
    else:
        logger.warning(
            "GATEWAY_ADMIN_KEY is not set. "
            "Use POST /admin/keys to create an admin key, or set the env var."
        )

    # 4. Register guardrails from config
    #    Injection detector is always on (zero cost, always worth having)
    guardrails_pipeline.register(InjectionGuardrail())

    #    Domain policy — built from DOMAIN_TOPICS + DOMAIN_THRESHOLD in .env
    if settings.enable_domain_policy:
        topics = settings.get_domain_topics()
        validator = build_domain_policy(
            topics=topics,
            threshold=settings.domain_threshold,
        )
        guardrails_pipeline.register(DomainGuardrail(validator))
        logger.info(
            f"Domain policy active: {len(topics)} topics, "
            f"threshold={settings.domain_threshold}, "
            f"system_prompt='{settings.default_system_prompt[:60]}...'"
        )
    else:
        logger.info("Domain policy disabled via ENABLE_DOMAIN_POLICY=false")

    logger.info("Sentri started")
    yield

    # ── Shutdown ───────────────────────────────────────────────────
    metrics._flush()
    logger.info("Sentri stopped")


app = FastAPI(
    title="Sentri",
    description=(
        "Production-grade LLM gateway with semantic caching, multi-layer guardrails, and API key auth.\n\n"
        "**Authentication:** All `/v1/*` endpoints require `X-API-Key` header.\n"
        "Admin endpoints additionally require a key with `role=admin`.\n\n"
        "**First-time setup:** Set `GATEWAY_ADMIN_KEY` in `.env` to bootstrap "
        "your first admin key, then use `POST /admin/keys` to create caller keys."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Rate limiting middleware
_redis_rl = Redis.from_url(settings.redis_url, decode_responses=True)
app.add_middleware(
    RateLimiterMiddleware,
    redis_client=_redis_rl,
    limit=settings.rate_limit_requests,
    window=settings.rate_limit_window,
)

app.include_router(router)
app.include_router(admin_router)
