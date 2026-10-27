"""FastAPI endpoints for Rules of Engagement (RoE) presets and document ingestion."""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from app.data.presets import ROE_PRESETS
from app.db import fetch_custom_roes, fetch_roe_presets, save_custom_roe
from app.engine.roe_parser import parse_unstructured_roe
from app.models.roe import RoeScope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/roe", tags=["Rules of Engagement"])


class ParseTextRequest(BaseModel):
    """Raw text payload for RoE document extraction."""

    content: str = Field(..., description="Markdown or plaintext RoE document text.")
    filename: Optional[str] = Field(default="custom_roe.md", description="Optional source filename.")


@router.get("/presets", response_model=List[RoeScope])
async def get_roe_presets() -> List[RoeScope]:
    """Retrieve all privacy-preserving pre-configured RoE templates.
    
    Tries Supabase PostgreSQL first; falls back cleanly to local static presets.
    """
    try:
        db_presets = fetch_roe_presets()
        if db_presets:
            # Map database records to RoeScope instances
            cleaned = []
            for r in db_presets:
                cleaned.append(
                    RoeScope(
                        roe_id=r.get("roe_id"),
                        name=r.get("name"),
                        engagement_type=r.get("engagement_type"),
                        summary=r.get("summary"),
                        allowed_cidrs=r.get("allowed_cidrs") or [],
                        allowed_domains=r.get("allowed_domains") or [],
                        target_hosts=r.get("target_hosts") or [],
                        prohibited_ips=r.get("prohibited_ips") or [],
                        allowed_tools=r.get("allowed_tools") or [],
                        prohibited_tools=r.get("prohibited_tools") or [],
                        prohibited_flags=r.get("prohibited_flags") or [],
                        prohibited_actions=r.get("prohibited_actions") or [],
                        max_nmap_timing=r.get("max_nmap_timing", 3),
                    )
                )
            return cleaned
    except Exception as e:
        logger.warning(f"Could not load presets from Supabase: {e}; falling back to static.")

    return ROE_PRESETS


@router.get("/custom", response_model=List[Dict[str, Any]])
async def get_custom_roes(
    user_id: Optional[str] = Query(default=None, description="Optional Supabase Auth user ID"),
) -> List[Dict[str, Any]]:
    """Retrieve custom scopes uploaded and saved to Supabase PostgreSQL."""
    return fetch_custom_roes(user_id=user_id)


@router.post("/parse-document", response_model=RoeScope)
async def parse_roe_document(
    file: UploadFile = File(...),
    user_id: Optional[str] = Query(default=None, description="Optional Supabase user UUID"),
) -> RoeScope:
    """Upload and parse an unstructured .md or .txt RoE document using LLM extraction."""
    filename = file.filename or "uploaded_roe.md"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ["md", "txt", "markdown"]:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload a Markdown (.md) or Plaintext (.txt) document.",
        )

    content_bytes = await file.read()
    if len(content_bytes) > 500 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds 500 KB upload limit.")

    try:
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Document must be valid UTF-8 encoded text.")

    try:
        scope = await parse_unstructured_roe(content_text, filename=filename)
        # Asynchronously persist custom RoE in Supabase
        save_custom_roe(scope.model_dump(), user_id=user_id, raw_document=content_text)
        return scope
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/parse-text", response_model=RoeScope)
async def parse_roe_text(
    request: ParseTextRequest,
    user_id: Optional[str] = Query(default=None, description="Optional Supabase user UUID"),
) -> RoeScope:
    """Parse raw pasted RoE text directly without multipart file upload."""
    try:
        scope = await parse_unstructured_roe(request.content, filename=request.filename or "custom_roe.md")
        save_custom_roe(scope.model_dump(), user_id=user_id, raw_document=request.content)
        return scope
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
