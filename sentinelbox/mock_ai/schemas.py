"""Request/response models for the mock AI API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .scenarios import Mode, Scenario

MAX_PROMPT_CHARS = 4000


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    mode: Mode = Mode.VULNERABLE
    scenario: Scenario | None = Field(
        default=None,
        description="Force a scenario regardless of the prompt (keeps tests deterministic).",
    )

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("prompt must not be blank")
        return value


class ChatMeta(BaseModel):
    """Ground truth about how the mock decided to answer.

    This exists so tests can measure a rule engine's accuracy. A rule engine
    under test must evaluate ``response`` only and must never read ``meta``.
    """

    scenario: Scenario
    mode: Mode
    matched_rule: str | None
    deterministic: bool = True


class ChatResponse(BaseModel):
    model: str
    response: str
    meta: ChatMeta


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ScenarioInfo(BaseModel):
    id: Scenario
    description: str
    example_prompt: str


class ScenariosResponse(BaseModel):
    modes: list[Mode]
    scenarios: list[ScenarioInfo]
