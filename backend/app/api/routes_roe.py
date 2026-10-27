"""FastAPI endpoints for Rules of Engagement (RoE) presets."""

from typing import List
from fastapi import APIRouter
from app.data.presets import ROE_PRESETS
from app.models.roe import RoeScope

router = APIRouter(prefix="/api/roe", tags=["Rules of Engagement"])


@router.get("/presets", response_model=List[RoeScope])
async def get_roe_presets() -> List[RoeScope]:
    """Retrieve all privacy-preserving pre-configured RoE templates."""
    return ROE_PRESETS
