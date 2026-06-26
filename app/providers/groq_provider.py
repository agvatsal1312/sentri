from groq import AsyncGroq
from app.providers.base import BaseLLMProvider, LLMRequest, LLMResponse
from app.core.config import settings

class GroqProvider(BaseLLMProvider):
    def __init__(self):
        self.client = AsyncGroq(api_key=settings.groq_api_key)
        self.model = "llama-3.1-8b-instant"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.message}
            ],
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )

        usage = response.usage
        return LLMResponse(
            content=response.choices[0].message.content,
            provider="groq",
            model=self.model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens
        )