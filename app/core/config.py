from pydantic_settings import BaseSettings
from typing import Optional


# Default topics used when DOMAIN_TOPICS is not set in .env
_DEFAULT_TOPICS = [
    "arrays and strings",
    "linked lists",
    "stacks and queues",
    "trees and binary search trees",
    "graphs and graph traversal",
    "dynamic programming",
    "recursion and backtracking",
    "sorting and searching algorithms",
    "hash maps and hash tables",
    "heaps and priority queues",
    "time complexity and space complexity",
    "coding interview problems",
    "data structures",
    "algorithms",
    "two sum and array problems",
    "leetcode problems",
    "competitive programming",
]

_DEFAULT_SYSTEM_PROMPT = "You are a helpful DSA tutor."


class Settings(BaseSettings):
    # LLM Providers
    openai_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Semantic Cache
    similarity_threshold: float = 0.85
    cache_ttl: int = 3600

    # Guardrails
    enable_pii_detection: bool = True
    enable_toxicity_check: bool = True
    enable_domain_policy: bool = True

    # Domain policy — fully configurable
    # Comma-separated list of allowed topics, e.g.:
    #   DOMAIN_TOPICS="python programming,web development,REST APIs"
    # Leave unset to use the default DSA tutor topics.
    domain_topics: Optional[str] = None
    domain_threshold: float = 0.30

    # Default system prompt sent to the LLM on every request.
    # Override to change the assistant's role entirely, e.g.:
    #   DEFAULT_SYSTEM_PROMPT="You are a helpful customer support agent for Acme Corp."
    default_system_prompt: str = _DEFAULT_SYSTEM_PROMPT

    # Rate limiting
    rate_limit_requests: int = 60
    rate_limit_window: int = 60

    # Circuit breaker
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout: float = 60.0

    # Auth
    gateway_admin_key: Optional[str] = None

    # App
    app_env: str = "development"
    log_level: str = "INFO"

    def get_domain_topics(self) -> list[str]:
        """
        Returns the list of allowed topics.
        If DOMAIN_TOPICS is set in .env, parses it as a comma-separated list.
        Otherwise falls back to the default DSA topic set.
        """
        if self.domain_topics:
            return [t.strip() for t in self.domain_topics.split(",") if t.strip()]
        return _DEFAULT_TOPICS

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
