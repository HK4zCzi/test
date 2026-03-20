from typing import Optional
from fastapi import HTTPException
from app.domain.asset import Asset, AssetStats
from app.repository.asset_repository import AssetRepository

MAX_BATCH = 100


class AssetUsecase:
    def __init__(self, repo: AssetRepository):
        self.repo = repo

    # ── Bài 1.1 ────────────────────────────────────────────────────
    async def get_stats(self) -> AssetStats:
        return await self.repo.get_stats()

    # ── Bài 1.2 ────────────────────────────────────────────────────
    async def count_by_filter(
        self, asset_type: Optional[str], status: Optional[str]
    ) -> int:
        return await self.repo.count_by_filter(asset_type, status)

    # ── Bài 2 ──────────────────────────────────────────────────────
    async def batch_create(self, assets: list[Asset]) -> list[str]:
        if not assets:
            raise HTTPException(400, detail="assets list cannot be empty")
        if len(assets) > MAX_BATCH:
            raise HTTPException(
                400, detail=f"too many assets: max {MAX_BATCH} per request"
            )
        # Pydantic already validated each asset's type/name in domain layer
        return await self.repo.batch_create(assets)

    # ── Bài 3 ──────────────────────────────────────────────────────
    async def batch_delete(self, ids: list[str]) -> tuple[int, int]:
        if not ids:
            raise HTTPException(400, detail="ids cannot be empty")
        if len(ids) > MAX_BATCH:
            raise HTTPException(
                400, detail=f"too many ids: max {MAX_BATCH} per request"
            )
        # Deduplicate to avoid double-counting
        unique_ids = list(dict.fromkeys(ids))
        return await self.repo.batch_delete(unique_ids)

    # ── Helpers ────────────────────────────────────────────────────
    async def create_one(self, asset: Asset) -> str:
        return await self.repo.create_one(asset)

    async def get_by_id(self, asset_id: str) -> dict:
        result = await self.repo.get_by_id(asset_id)
        if not result:
            raise HTTPException(404, detail=f"asset {asset_id} not found")
        return result

    # ── Bài 6: Pagination ──────────────────────────────────────────
    async def list_assets(
        self,
        asset_type: Optional[str],
        status: Optional[str],
        page: int,
        limit: int,
    ) -> tuple[list[dict], int]:
        if page < 1:
            raise HTTPException(400, detail="page must be >= 1")
        if limit < 1 or limit > 100:
            raise HTTPException(400, detail="limit must be between 1 and 100")
        return await self.repo.list_assets(asset_type, status, page, limit)

    # ── Bài 7: Search ──────────────────────────────────────────────
    async def search_by_name(self, query: str) -> list[dict]:
        query = query.strip()
        if not query:
            raise HTTPException(400, detail="search query cannot be empty")
        if len(query) < 2:
            raise HTTPException(400, detail="search query must be at least 2 characters")
        return await self.repo.search_by_name(query)
