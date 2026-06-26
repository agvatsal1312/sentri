from abc import ABC, abstractmethod
from pydantic import BaseModel
from typing import Optional

class LLMRequest(BaseModel):
    message: str
    system_prompt: Optional[str] = "You are a helpful assistant."
    temperature: float = 0.7
    max_tokens: int = 1024

class LLMResponse(BaseModel):
    content: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

class BaseLLMProvider(ABC):
    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        pass