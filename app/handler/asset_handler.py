import math
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from app.domain.asset import Asset, AssetType, AssetStatus
from app.usecase.asset_usecase import AssetUsecase


def create_router(usecase: AssetUsecase) -> APIRouter:
    router = APIRouter(prefix="/assets", tags=["assets"])

    # ════════════════════════════════════════════════════════════════
    # Bài 1.1 — GET /assets/stats
    # ════════════════════════════════════════════════════════════════
    @router.get("/stats", summary="Get asset statistics")
    async def get_stats():
        return await usecase.get_stats()

    # ════════════════════════════════════════════════════════════════
    # Bài 1.2 — GET /assets/count
    # ════════════════════════════════════════════════════════════════
    @router.get("/count", summary="Count assets with optional filters")
    async def count_assets(
        type: Optional[AssetType] = Query(None),
        status: Optional[AssetStatus] = Query(None),
    ):
        count = await usecase.count_by_filter(
            type.value if type else None,
            status.value if status else None,
        )
        return {
            "count": count,
            "filters": {
                "type": type.value if type else None,
                "status": status.value if status else None,
            },
        }

    # ════════════════════════════════════════════════════════════════
    # Bài 2 — POST /assets/batch
    # ════════════════════════════════════════════════════════════════
    class BatchCreateRequest(BaseModel):
        assets: list[Asset]

        @field_validator("assets")
        @classmethod
        def must_not_be_empty(cls, v):
            if not v:
                raise ValueError("assets list cannot be empty")
            return v

    @router.post("/batch", status_code=201, summary="Batch create assets in one transaction")
    async def batch_create(req: BatchCreateRequest):
        ids = await usecase.batch_create(req.assets)
        return {"created": len(ids), "ids": ids}

    # ════════════════════════════════════════════════════════════════
    # Bài 3 — DELETE /assets/batch
    # ════════════════════════════════════════════════════════════════
    @router.delete("/batch", summary="Batch delete assets by IDs")
    async def batch_delete(
        ids: str = Query(..., description="Comma-separated asset IDs"),
    ):
        id_list = [i.strip() for i in ids.split(",") if i.strip()]
        if not id_list:
            raise HTTPException(400, detail="No valid IDs provided")
        deleted, not_found = await usecase.batch_delete(id_list)
        return {"deleted": deleted, "not_found": not_found}

    # ════════════════════════════════════════════════════════════════
    # Bài 6 — GET /assets  (Pagination & Filtering) BONUS
    # ════════════════════════════════════════════════════════════════
    @router.get("", summary="List assets with pagination and filters")
    async def list_assets(
        page: int = Query(1, ge=1, description="Page number"),
        limit: int = Query(20, ge=1, le=100, description="Items per page"),
        type: Optional[AssetType] = Query(None, description="Filter by type"),
        status: Optional[AssetStatus] = Query(None, description="Filter by status"),
    ):
        data, total = await usecase.list_assets(
            asset_type=type.value if type else None,
            status=status.value if status else None,
            page=page,
            limit=limit,
        )
        total_pages = math.ceil(total / limit) if total > 0 else 1
        return {
            "data": data,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages,
            },
        }

    # ════════════════════════════════════════════════════════════════
    # Bài 7 — GET /assets/search  (Search by Name) BONUS
    # ════════════════════════════════════════════════════════════════
    @router.get("/search", summary="Search assets by name (partial, case-insensitive)")
    async def search_assets(
        q: str = Query(..., min_length=2, description="Search keyword"),
    ):
        results = await usecase.search_by_name(q)
        return {"results": results, "count": len(results)}

    # ════════════════════════════════════════════════════════════════
    # Single create & get — helpers cho test
    # ════════════════════════════════════════════════════════════════
    @router.post("/single", status_code=201, summary="Create single asset")
    async def create_asset(asset: Asset):
        asset_id = await usecase.create_one(asset)
        return {"id": asset_id, "name": asset.name, "type": asset.type, "status": asset.status}

    @router.get("/{asset_id}", summary="Get asset by ID")
    async def get_asset(asset_id: str):
        return await usecase.get_by_id(asset_id)

    return router
