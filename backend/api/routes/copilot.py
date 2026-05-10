"""Routes for the DarkShield analyst copilot."""

from __future__ import annotations

import json
import logging
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from api.dependencies.auth import require_current_user
from api.schemas.auth import AuthUser
from api.schemas.copilot import CopilotRequest, CopilotResponse
from api.services.copilot_service import copilot_service


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api/copilot", tags=["copilot"])


@router.post("/chat", response_model=CopilotResponse)
async def chat(payload: CopilotRequest, current_user: AuthUser = Depends(require_current_user)) -> CopilotResponse:
    try:
        return await copilot_service.answer(payload, current_user)
    except ValueError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Copilot unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected copilot failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to generate copilot response.") from exc


@router.post("/chat/stream")
async def chat_stream(
    payload: CopilotRequest,
    current_user: AuthUser = Depends(require_current_user),
) -> StreamingResponse:
    try:
        response = await copilot_service.answer(payload, current_user)
    except ValueError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Copilot unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected copilot failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to generate copilot response.") from exc

    async def event_stream() -> AsyncIterator[str]:
        meta = response.model_dump(
            include={
                "question",
                "analysis_type",
                "confidence",
                "sources",
                "supporting_findings",
                "metrics",
            }
        )
        yield f"event: meta\ndata: {json.dumps(meta, default=str)}\n\n"

        answer_text = response.answer.strip()
        chunk_size = 32
        for index in range(0, len(answer_text), chunk_size):
            chunk = answer_text[index : index + chunk_size]
            yield f"event: chunk\ndata: {json.dumps({'chunk': chunk})}\n\n"

        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
