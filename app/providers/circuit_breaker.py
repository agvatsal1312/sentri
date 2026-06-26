"""
Circuit breaker for LLM providers.
States: CLOSED (normal) → OPEN (failing) → HALF_OPEN (testing recovery)
"""
import time
import asyncio
import logging
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing — reject requests immediately
    HALF_OPEN = "half_open" # Testing if provider has recovered


@dataclass
class CircuitBreaker:
    provider_name: str
    failure_threshold: int = 5       # failures before opening
    recovery_timeout: float = 60.0   # seconds before attempting recovery
    half_open_max_calls: int = 2     # test calls allowed in HALF_OPEN

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _half_open_calls: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                logger.info(f"[{self.provider_name}] Circuit moving OPEN → HALF_OPEN")
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state

    def is_available(self) -> bool:
        s = self.state
        if s == CircuitState.CLOSED:
            return True
        if s == CircuitState.HALF_OPEN:
            return self._half_open_calls < self.half_open_max_calls
        return False  # OPEN

    def record_success(self):
        if self._state == CircuitState.HALF_OPEN:
            logger.info(f"[{self.provider_name}] Recovery confirmed — circuit CLOSED")
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0

    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._state == CircuitState.HALF_OPEN:
            logger.warning(f"[{self.provider_name}] Recovery failed — circuit re-OPEN")
            self._state = CircuitState.OPEN
        elif self._failure_count >= self.failure_threshold:
            logger.error(
                f"[{self.provider_name}] {self._failure_count} failures — circuit OPEN "
                f"(retry in {self.recovery_timeout}s)"
            )
            self._state = CircuitState.OPEN

    def increment_half_open(self):
        self._half_open_calls += 1

    def status_dict(self) -> dict:
        return {
            "state": self.state.value,
            "failure_count": self._failure_count,
            "last_failure_ago_s": (
                round(time.monotonic() - self._last_failure_time, 1)
                if self._last_failure_time else None
            ),
        }
