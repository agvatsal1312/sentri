"""
Guardrails pipeline — plugin-style registry.

Adding a new guardrail: create a module in app/guardrails/, define a class
that implements InputGuardrail, then call pipeline.register() at startup.
No edits to this file needed.
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.guardrails.pii_detector import pii_detector
from app.guardrails.injection_detector import injection_detector
from app.guardrails.domain_policy import build_domain_policy, DomainPolicyValidator
from app.core.config import settings

logger = logging.getLogger(__name__)

_MAX_REQUEST_BYTES = 32_768  # 32 KB


@dataclass
class GuardrailResult:
    passed: bool
    scrubbed_text: str
    blocked_reason: str | None
    pii_detected: list
    injection_detected: bool
    domain_allowed: bool


class InputGuardrail(ABC):
    @abstractmethod
    def check(self, text: str) -> GuardrailResult:
        ...


# ------------------------------------------------------------------
# Built-in guardrail plugins
# ------------------------------------------------------------------

class InjectionGuardrail(InputGuardrail):
    def check(self, text: str) -> GuardrailResult:
        result = injection_detector.detect(text)
        if result.is_injection:
            return GuardrailResult(
                passed=False, scrubbed_text=text,
                blocked_reason=result.reason, pii_detected=[],
                injection_detected=True, domain_allowed=True,
            )
        return GuardrailResult(
            passed=True, scrubbed_text=text, blocked_reason=None,
            pii_detected=[], injection_detected=False, domain_allowed=True,
        )


class DomainGuardrail(InputGuardrail):
    def __init__(self, validator: DomainPolicyValidator):
        self._validator = validator

    def check(self, text: str) -> GuardrailResult:
        result = self._validator.validate(text)
        return GuardrailResult(
            passed=result.is_allowed, scrubbed_text=text,
            blocked_reason=result.reason if not result.is_allowed else None,
            pii_detected=[], injection_detected=False,
            domain_allowed=result.is_allowed,
        )


# ------------------------------------------------------------------
# Pipeline
# ------------------------------------------------------------------

class GuardrailsPipeline:
    def __init__(self):
        self._input_guardrails: list[InputGuardrail] = []

    def register(self, guardrail: InputGuardrail):
        self._input_guardrails.append(guardrail)
        logger.info(f"Registered guardrail: {type(guardrail).__name__}")

    async def run_input(self, text: str) -> GuardrailResult:
        # Hard size limit
        if len(text.encode("utf-8")) > _MAX_REQUEST_BYTES:
            return GuardrailResult(
                passed=False, scrubbed_text=text,
                blocked_reason=f"Request too large (max {_MAX_REQUEST_BYTES // 1024}KB)",
                pii_detected=[], injection_detected=False, domain_allowed=True,
            )

        # Registered sync guardrails
        for guardrail in self._input_guardrails:
            result = guardrail.check(text)
            if not result.passed:
                return result

        # Async PII scrubbing
        scrubbed_text = text
        pii_found: list = []
        if settings.enable_pii_detection:
            scrubbed_text, pii_found = await asyncio.to_thread(pii_detector.scrub, text)

        return GuardrailResult(
            passed=True, scrubbed_text=scrubbed_text, blocked_reason=None,
            pii_detected=pii_found, injection_detected=False, domain_allowed=True,
        )

    async def run_output(self, text: str) -> tuple[str, list]:
        if settings.enable_pii_detection:
            return await asyncio.to_thread(pii_detector.scrub, text)
        return text, []


# ------------------------------------------------------------------
# Singleton — registered at startup in main.py using config values
# ------------------------------------------------------------------
guardrails_pipeline = GuardrailsPipeline()
