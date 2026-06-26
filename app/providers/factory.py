import logging
from app.providers.base import BaseLLMProvider, LLMRequest, LLMResponse
from app.providers.groq_provider import GroqProvider
from app.providers.circuit_breaker import CircuitBreaker

logger = logging.getLogger(__name__)

# Instantiate providers and their circuit breakers once
_providers: dict[str, BaseLLMProvider] = {}
_breakers: dict[str, CircuitBreaker] = {}

# Fallback order: if requested provider is unavailable, try these in order
_FALLBACK_CHAIN: list[str] = ["groq"]


def _init_provider(name: str) -> BaseLLMProvider:
    if name == "groq":
        return GroqProvider()
    raise ValueError(f"Unknown provider: {name}")


def get_provider(name: str = "groq") -> BaseLLMProvider:
    """Return the provider instance (no circuit-breaker logic here — use call_with_fallback)."""
    if name not in _providers:
        _providers[name] = _init_provider(name)
        _breakers[name] = CircuitBreaker(provider_name=name)
    return _providers[name]


def get_breaker(name: str) -> CircuitBreaker:
    get_provider(name)  # ensures initialisation
    return _breakers[name]


async def call_with_fallback(name: str, request: LLMRequest) -> tuple[LLMResponse, str]:
    """
    Try the requested provider; if its circuit is OPEN or the call fails,
    walk the fallback chain.  Returns (LLMResponse, actual_provider_name).
    """
    # Build the ordered list: requested provider first, then fallbacks (deduplicated)
    chain = [name] + [p for p in _FALLBACK_CHAIN if p != name]

    last_exc: Exception | None = None
    for provider_name in chain:
        provider = get_provider(provider_name)
        breaker = get_breaker(provider_name)

        if not breaker.is_available():
            logger.warning(f"[{provider_name}] Circuit is {breaker.state.value} — skipping")
            continue

        if breaker.state.value == "half_open":
            breaker.increment_half_open()

        try:
            response = await provider.complete(request)
            breaker.record_success()
            return response, provider_name
        except Exception as exc:
            logger.error(f"[{provider_name}] Call failed: {exc}")
            breaker.record_failure()
            last_exc = exc
            continue

    raise RuntimeError(
        f"All providers exhausted. Last error: {last_exc}"
    )


def circuit_status() -> dict:
    """Return circuit state for every known provider (used by /metrics)."""
    return {
        name: _breakers[name].status_dict()
        for name in _breakers
    }
