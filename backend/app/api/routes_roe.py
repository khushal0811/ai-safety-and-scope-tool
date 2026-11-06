"""FastAPI endpoints for Rules of Engagement document ingestion and custom scopes."""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from app.api.deps import get_authenticated_user_id, require_authenticated_user_id
from app.db import fetch_custom_roes, save_custom_roe
from app.engine.roe_parser import parse_unstructured_roe
from app.models.roe import RoeScope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/roe", tags=["Rules of Engagement"])


class ParseTextRequest(BaseModel):
    """Raw text payload for RoE document extraction."""

    content: str = Field(..., max_length=500 * 1024, description="Markdown or plaintext RoE document text.")
    filename: Optional[str] = Field(default="custom_roe.md", description="Optional source filename.")


@router.get("/custom", response_model=List[Dict[str, Any]])
async def get_custom_roes(
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> List[Dict[str, Any]]:
    """Retrieve custom scopes uploaded and saved to Supabase PostgreSQL."""
    return fetch_custom_roes(user_id=user_id)


@router.get("/custom/{roe_id}", response_model=RoeScope)
async def get_custom_roe_by_id(
    roe_id: str,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> RoeScope:
    """Retrieve one saved custom scope so a historical audit can restore it."""
    from app.db import fetch_custom_roe_by_id
    from app.engine.roe_integrity import roe_scope_from_row

    row = fetch_custom_roe_by_id(roe_id, user_id=user_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Unknown custom scope: {roe_id!r}")
    return roe_scope_from_row(row)


@router.post("/parse-document", response_model=RoeScope)
async def parse_roe_document(
    file: UploadFile = File(...),
    # LLM-backed extraction spends the server's key: require a verified user
    user_id: str = Depends(require_authenticated_user_id),
) -> RoeScope:
    """Upload and parse an unstructured .md or .txt RoE document using LLM extraction."""
    filename = file.filename or "uploaded_roe.md"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ["md", "txt", "markdown"]:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload a Markdown (.md) or Plaintext (.txt) document.",
        )

    # Read at most the limit plus one byte, so an oversized upload is never fully buffered
    content_bytes = await file.read(500 * 1024 + 1)
    if len(content_bytes) > 500 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds 500 KB upload limit.")

    try:
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Document must be valid UTF-8 encoded text.")

    try:
        scope = await parse_unstructured_roe(content_text, filename=filename)
        # Asynchronously persist custom RoE in Supabase
        await run_in_threadpool(save_custom_roe, scope.model_dump(), user_id=user_id, raw_document=content_text)
        return scope
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/parse-text", response_model=RoeScope)
async def parse_roe_text(
    request: ParseTextRequest,
    # LLM-backed extraction spends the server's key: require a verified user
    user_id: str = Depends(require_authenticated_user_id),
) -> RoeScope:
    """Parse raw pasted RoE text directly without multipart file upload."""
    try:
        scope = await parse_unstructured_roe(request.content, filename=request.filename or "custom_roe.md")
        await run_in_threadpool(save_custom_roe, scope.model_dump(), user_id=user_id, raw_document=request.content)
        return scope
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
