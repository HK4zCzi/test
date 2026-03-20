import asyncpg
import uuid
import json
from datetime import datetime, timezone
from typing import Optional
from app.domain.scan import ScanJob, ScanStatus, ScanType


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_job(row) -> dict:
    d = dict(row)
    # Convert datetime objects to ISO strings
    for field in ("started_at", "ended_at", "created_at"):
        if d.get(field) and hasattr(d[field], "strftime"):
            d[field] = d[field].strftime("%Y-%m-%dT%H:%M:%SZ")
    return d


class ScanRepository:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    # ── Scan Jobs ────────────────────────────────────────────────────
    async def create_job(self, asset_id: str, scan_type: str) -> dict:
        job_id = str(uuid.uuid4())
        now = _now()
        await self.pool.execute(
            """
            INSERT INTO scan_jobs (id, asset_id, scan_type, status, started_at, created_at)
            VALUES ($1, $2, $3, 'pending', NOW(), NOW())
            """,
            job_id, asset_id, scan_type,
        )
        row = await self.pool.fetchrow("SELECT * FROM scan_jobs WHERE id = $1", job_id)
        return _row_to_job(row)

    async def get_job(self, job_id: str) -> Optional[dict]:
        row = await self.pool.fetchrow("SELECT * FROM scan_jobs WHERE id = $1", job_id)
        return _row_to_job(row) if row else None

    async def list_jobs_for_asset(self, asset_id: str) -> list[dict]:
        rows = await self.pool.fetch(
            "SELECT * FROM scan_jobs WHERE asset_id = $1 ORDER BY created_at DESC",
            asset_id,
        )
        return [_row_to_job(r) for r in rows]

    async def update_job_status(
        self,
        job_id: str,
        status: str,
        error: str = "",
        results_count: int = 0,
    ) -> None:
        await self.pool.execute(
            """
            UPDATE scan_jobs
            SET status = $1, ended_at = NOW(), error = $2, results = $3
            WHERE id = $4
            """,
            status, error, results_count, job_id,
        )

    async def set_job_running(self, job_id: str) -> None:
        await self.pool.execute(
            "UPDATE scan_jobs SET status = 'running', started_at = NOW() WHERE id = $1",
            job_id,
        )

    # ── Scan Results ─────────────────────────────────────────────────
    async def save_results(self, job_id: str, results: list[dict]) -> None:
        """Save a list of result dicts into scan_results table (JSONB)"""
        records = [
            (str(uuid.uuid4()), job_id, json.dumps(r))
            for r in results
        ]
        await self.pool.executemany(
            "INSERT INTO scan_results (id, job_id, data) VALUES ($1, $2, $3::jsonb)",
            records,
        )

    async def get_results(self, job_id: str) -> list[dict]:
        rows = await self.pool.fetch(
            "SELECT data FROM scan_results WHERE job_id = $1 ORDER BY created_at ASC",
            job_id,
        )
        return [json.loads(r["data"]) for r in rows]

    async def get_all_results_for_asset(self, asset_id: str) -> list[dict]:
        """Aggregate all scan results across all jobs for an asset"""
        rows = await self.pool.fetch(
            """
            SELECT sr.data, sj.scan_type, sj.created_at
            FROM scan_results sr
            JOIN scan_jobs sj ON sr.job_id = sj.id
            WHERE sj.asset_id = $1
            ORDER BY sj.created_at DESC
            """,
            asset_id,
        )
        return [
            {**json.loads(r["data"]), "scan_type": r["scan_type"]}
            for r in rows
        ]
