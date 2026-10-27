"""FastAPI endpoints for Rules of Engagement (RoE) presets and document ingestion."""

from typing import List, Optional
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from app.data.presets import ROE_PRESETS
from app.engine.roe_parser import parse_unstructured_roe
from app.models.roe import RoeScope

router = APIRouter(prefix="/api/roe", tags=["Rules of Engagement"])


class ParseTextRequest(BaseModel):
    """Raw text payload for RoE document extraction."""

    content: str = Field(..., description="Markdown or plaintext RoE document text.")
    filename: Optional[str] = Field(default="custom_roe.md", description="Optional source filename.")


@router.get("/presets", response_model=List[RoeScope])
async def get_roe_presets() -> List[RoeScope]:
    """Retrieve all privacy-preserving pre-configured RoE templates."""
    return ROE_PRESETS


@router.post("/parse-document", response_model=RoeScope)
async def parse_roe_document(file: UploadFile = File(...)) -> RoeScope:
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
        return await parse_unstructured_roe(content_text, filename=filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/parse-text", response_model=RoeScope)
async def parse_roe_text(request: ParseTextRequest) -> RoeScope:
    """Parse raw pasted RoE text directly without multipart file upload."""
    try:
        return await parse_unstructured_roe(request.content, filename=request.filename or "custom_roe.md")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
