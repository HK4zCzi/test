import asyncpg
import uuid
from typing import Optional
from app.domain.asset import Asset, AssetStats


class AssetRepository:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    # ── Bài 1.1 ────────────────────────────────────────────────────
    async def get_stats(self) -> AssetStats:
        async with self.pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM assets") or 0

            type_rows = await conn.fetch(
                "SELECT type, COUNT(*)::int AS cnt FROM assets GROUP BY type"
            )
            status_rows = await conn.fetch(
                "SELECT status, COUNT(*)::int AS cnt FROM assets GROUP BY status"
            )

        return AssetStats(
            total=total,
            by_type={r["type"]: r["cnt"] for r in type_rows},
            by_status={r["status"]: r["cnt"] for r in status_rows},
        )

    # ── Bài 1.2 ────────────────────────────────────────────────────
    async def count_by_filter(
        self, asset_type: Optional[str], status: Optional[str]
    ) -> int:
        # ALWAYS use parameterized queries — never f-string user input into SQL
        conditions, args = [], []

        if asset_type:
            args.append(asset_type)
            conditions.append(f"type = ${len(args)}")
        if status:
            args.append(status)
            conditions.append(f"status = ${len(args)}")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        result = await self.pool.fetchval(
            f"SELECT COUNT(*) FROM assets {where}", *args
        )
        return result or 0

    # ── Bài 2 ──────────────────────────────────────────────────────
    async def batch_create(self, assets: list[Asset]) -> list[str]:
        ids = [str(uuid.uuid4()) for _ in assets]

        async with self.pool.acquire() as conn:
            # transaction: if ANY insert fails → rollback ALL
            async with conn.transaction():
                await conn.executemany(
                    """
                    INSERT INTO assets (id, name, type, status)
                    VALUES ($1, $2, $3, $4)
                    """,
                    [
                        (ids[i], a.name, a.type.value, a.status.value)
                        for i, a in enumerate(assets)
                    ],
                )
        return ids

    # ── Bài 3 ──────────────────────────────────────────────────────
    async def batch_delete(self, ids: list[str]) -> tuple[int, int]:
        if not ids:
            return 0, 0

        # Parameterized IN clause
        placeholders = ", ".join(f"${i + 1}" for i in range(len(ids)))
        result = await self.pool.execute(
            f"DELETE FROM assets WHERE id IN ({placeholders})", *ids
        )
        # asyncpg returns "DELETE N"
        deleted = int(result.split()[-1])
        not_found = len(ids) - deleted
        return deleted, not_found

    # ── Single create (dùng cho test bài 3) ────────────────────────
    async def create_one(self, asset: Asset) -> str:
        asset_id = str(uuid.uuid4())
        await self.pool.execute(
            "INSERT INTO assets (id, name, type, status) VALUES ($1, $2, $3, $4)",
            asset_id, asset.name, asset.type.value, asset.status.value,
        )
        return asset_id

    # ── Get one (dùng để verify 404 sau delete) ─────────────────────
    async def get_by_id(self, asset_id: str) -> Optional[dict]:
        row = await self.pool.fetchrow(
            "SELECT * FROM assets WHERE id = $1", asset_id
        )
        return dict(row) if row else None

    # ── Bài 6: Pagination & Filtering ───────────────────────────────
    async def list_assets(
        self,
        asset_type: Optional[str],
        status: Optional[str],
        page: int,
        limit: int,
    ) -> tuple[list[dict], int]:
        conditions, args = [], []

        if asset_type:
            args.append(asset_type)
            conditions.append(f"type = ${len(args)}")
        if status:
            args.append(status)
            conditions.append(f"status = ${len(args)}")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * limit

        # Total count
        total = await self.pool.fetchval(
            f"SELECT COUNT(*) FROM assets {where}", *args
        ) or 0

        # Paginated rows
        args_paginated = args + [limit, offset]
        limit_ph  = f"${len(args) + 1}"
        offset_ph = f"${len(args) + 2}"

        rows = await self.pool.fetch(
            f"SELECT id, name, type, status FROM assets {where} "
            f"ORDER BY name ASC LIMIT {limit_ph} OFFSET {offset_ph}",
            *args_paginated,
        )
        return [dict(r) for r in rows], int(total)

    # ── Bài 7: Search by Name ────────────────────────────────────────
    async def search_by_name(self, query: str) -> list[dict]:
        # ILIKE = case-insensitive, parameterized chống SQL injection
        rows = await self.pool.fetch(
            "SELECT id, name, type, status FROM assets WHERE name ILIKE $1 LIMIT 100",
            f"%{query}%",
        )
        return [dict(r) for r in rows]
