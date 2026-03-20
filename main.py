import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from pkg.database import Database
from app.repository.asset_repository import AssetRepository
from app.repository.scan_repository import ScanRepository
from app.usecase.asset_usecase import AssetUsecase
from app.usecase.scan_usecase import ScanUsecase
from app.handler.asset_handler import create_router
from app.handler.scan_handler import create_scan_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/assets_db",
)

db = Database(DB_URL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect(max_retries=5, base_delay=1.0)

    # Wire all layers
    asset_repo = AssetRepository(db.pool)
    scan_repo  = ScanRepository(db.pool)
    asset_uc   = AssetUsecase(asset_repo)
    scan_uc    = ScanUsecase(scan_repo, asset_repo)

    app.include_router(create_router(asset_uc))
    app.include_router(create_scan_router(scan_uc))
    yield
    await db.close()


app = FastAPI(
    title="EASM Asset Management API",
    version="2.0.0",
    description="External Attack Surface Management — asset inventory + scanning",
    lifespan=lifespan,
)

# ── Bài 3: CORS middleware ────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Bài 5: Health Check ───────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health_check():
    result, status_code = await db.health_check()
    return JSONResponse(content=result, status_code=status_code)


@app.get("/", tags=["system"])
async def root():
    return {
        "app": "EASM API",
        "version": "2.0.0",
        "docs": "/docs",
    }
