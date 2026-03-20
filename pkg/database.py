import asyncpg
import asyncio
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: asyncpg.Pool | None = None

    async def connect(self, max_retries: int = 5, base_delay: float = 1.0):
        """Connect with exponential backoff retry (Bài 4)"""
        for attempt in range(1, max_retries + 1):
            print(f"🔄 Database connection attempt {attempt}/{max_retries}...")
            try:
                self.pool = await asyncpg.create_pool(
                    self.dsn,
                    min_size=2,
                    max_size=10,
                    command_timeout=30,
                )
                print("✅ Database connected successfully!")
                await self._migrate()
                return
            except Exception as e:
                delay = base_delay * (2 ** (attempt - 1))
                if attempt == max_retries:
                    print(f"❌ All {max_retries} attempts failed. Exiting.")
                    raise RuntimeError(f"Cannot connect to DB after {max_retries} attempts") from e
                print(f"⚠️  Connection failed: {e}. Retrying in {int(delay)}s...")
                await asyncio.sleep(delay)

    async def health_check(self) -> tuple[dict, int]:
        """Return DB health status (Bài 5)"""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not self.pool:
            return {"status": "degraded", "database": {"status": "disconnected"}, "timestamp": timestamp}, 503
        try:
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            size = self.pool.get_size()
            idle = self.pool.get_idle_size()
            return {
                "status": "ok",
                "database": {
                    "status": "connected",
                    "open_connections": size,
                    "in_use": size - idle,
                    "idle": idle,
                    "max_open": 10,
                },
                "timestamp": timestamp,
            }, 200
        except Exception as e:
            return {"status": "degraded", "database": {"status": "disconnected", "error": str(e)}, "timestamp": timestamp}, 503

    async def _migrate(self):
        """Create/update all tables"""
        async with self.pool.acquire() as conn:
            # Assets table (existing)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id         TEXT PRIMARY KEY,
                    name       TEXT NOT NULL,
                    type       TEXT NOT NULL CHECK (type IN ('domain', 'ip', 'service')),
                    status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            # Scan jobs table (new - bài 1)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id         TEXT PRIMARY KEY,
                    asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    scan_type  TEXT NOT NULL,
                    status     TEXT NOT NULL DEFAULT 'pending',
                    started_at TIMESTAMPTZ,
                    ended_at   TIMESTAMPTZ,
                    error      TEXT DEFAULT '',
                    results    INT DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            # Scan results table (new - bài 1)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id         TEXT PRIMARY KEY,
                    job_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                    data       JSONB NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_asset ON scan_jobs(asset_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_job ON scan_results(job_id)")
        print("✅ Migration complete")

    async def close(self):
        if self.pool:
            await self.pool.close()
