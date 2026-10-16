"""FastAPI application for the mock AI target.

Run locally (loopback only):

    uvicorn sentinelbox.mock_ai.app:app --host 127.0.0.1 --port 8001
"""

from __future__ import annotations

from fastapi import FastAPI, Request

from .. import __version__
from .engine import MODEL_NAME, respond
from .scenarios import CATALOG, Mode
from .schemas import (
    ChatMeta,
    ChatRequest,
    ChatResponse,
    HealthResponse,
    ScenarioInfo,
    ScenariosResponse,
)

SERVICE_NAME = "sentinelbox-mock-ai"
MOCK_HEADER = "X-SentinelBox-Mock"


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelBox Mock AI",
        version=__version__,
        description="Deterministic, offline mock AI target for adversarial testing. No real model is used.",
    )

    @app.middleware("http")
    async def mark_as_mock(request: Request, call_next):
        response = await call_next(request)
        response.headers[MOCK_HEADER] = "true"
        return response

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", service=SERVICE_NAME, version=__version__)

    @app.get("/scenarios", response_model=ScenariosResponse)
    def scenarios() -> ScenariosResponse:
        return ScenariosResponse(
            modes=list(Mode),
            scenarios=[
                ScenarioInfo(id=e.scenario, description=e.description, example_prompt=e.example_prompt)
                for e in CATALOG
            ],
        )

    @app.post("/chat", response_model=ChatResponse)
    def chat(request: ChatRequest) -> ChatResponse:
        result = respond(request.prompt, request.mode, request.scenario)
        return ChatResponse(
            model=MODEL_NAME,
            response=result.response,
            meta=ChatMeta(scenario=result.scenario, mode=result.mode, matched_rule=result.matched_rule),
        )

    return app


app = create_app()
