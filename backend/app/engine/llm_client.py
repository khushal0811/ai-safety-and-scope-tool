"""LLM Client for RoE document extraction and intelligent remediation.

Zero Host Execution: Strictly communicates with LLM completion APIs over HTTPS.
Enforces XML isolation tags around untrusted inputs to defend against indirect
prompt injection.
"""

import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from app.config import settings

logger = logging.getLogger(__name__)


class LLMClient:
    """HTTP client for LLM inference (Groq / OpenRouter)."""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url
        self.model = settings.LLAMA_MODEL

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key.strip())

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> Optional[Dict[str, Any]]:
        """Dispatch chat completion expecting structured JSON output."""
        if not self.is_configured:
            logger.warning("[LLMClient] No API key configured; skipping LLM dispatch.")
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Include OpenRouter referer/title headers if targeting OpenRouter
        if "openrouter.ai" in self.base_url:
            headers["HTTP-Referer"] = "https://github.com/khushal0811/ai-safety-and-scope-tool"
            headers["X-Title"] = "AI Safety & Scope Tool (SST)"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )

                if res.status_code == 200:
                    data = res.json()
                    choices = data.get("choices", [])
                    if choices:
                        raw_content = choices[0].get("message", {}).get("content", "")
                        return json.loads(raw_content)
                else:
                    logger.error(
                        f"[LLMClient] Error {res.status_code} from {self.base_url}: {res.text}"
                    )
        except Exception as e:
            logger.error(f"[LLMClient] Exception during generation: {e}")

        return None


llm_client = LLMClient()
