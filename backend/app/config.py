"""Application configuration using Pydantic Settings."""

from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Vallum Backend configuration settings."""

    HOST: str = "127.0.0.1"
    PORT: int = 8000
    ENVIRONMENT: str = "development"
    CORS_ORIGINS: Union[List[str], str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    OPENROUTER_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    DEFAULT_MODEL: str = "deepseek/deepseek-v4.1-flash"
    LLAMA_MODEL: str = "deepseek/deepseek-v4.1-flash"
    KEY_VAULT_MASTER_KEY: str = ""
    ATTESTATION_HMAC_KEY: str = ""
    BENCHMARK_MAX_RUNS_PER_USER_PER_DAY: int = 20
    BENCHMARK_MAX_CONCURRENT_JUDGES: int = 6
    BENCHMARK_INPUT_PRICE_PER_MILLION_USD: float = 0.0
    BENCHMARK_OUTPUT_PRICE_PER_MILLION_USD: float = 0.0
    BENCHMARK_JUDGE_INPUT_PRICE_PER_MILLION_USD: float = 0.0
    BENCHMARK_JUDGE_OUTPUT_PRICE_PER_MILLION_USD: float = 0.0

    @property
    def llm_provider(self) -> str:
        if self.OPENROUTER_API_KEY:
            return "openrouter"
        if self.GROQ_API_KEY:
            return "groq"
        return "none"

    @property
    def llm_api_key(self) -> str:
        return self.OPENROUTER_API_KEY or self.GROQ_API_KEY

    @property
    def llm_base_url(self) -> str:
        if self.OPENROUTER_API_KEY:
            return "https://openrouter.ai/api/v1"
        if self.GROQ_API_KEY:
            return "https://api.groq.com/openai/v1"
        return "https://openrouter.ai/api/v1"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


settings = Settings()
