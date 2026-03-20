import json
from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from app.usecase.scan_usecase import ScanUsecase


def create_scan_router(usecase: ScanUsecase) -> APIRouter:
    router = APIRouter(tags=["scans"])

    class StartScanRequest(BaseModel):
        scan_type: str

    @router.post("/assets/{asset_id}/scan", status_code=202)
    async def start_scan(asset_id: str, req: StartScanRequest):
        return await usecase.start_scan(asset_id, req.scan_type)

    @router.get("/scan-jobs/{job_id}")
    async def get_job(job_id: str):
        return await usecase.get_job(job_id)

    @router.get("/scan-jobs/{job_id}/results")
    async def get_results(job_id: str):
        return await usecase.get_results(job_id)

    @router.get("/assets/{asset_id}/scans")
    async def list_scans(asset_id: str):
        return await usecase.list_scans_for_asset(asset_id)

    @router.get("/assets/{asset_id}/results")
    async def get_asset_results(asset_id: str):
        results = await usecase.get_all_results_for_asset(asset_id)
        return {"asset_id": asset_id, "results": results}

    # ── Export endpoints ─────────────────────────────────────────
    @router.get("/assets/{asset_id}/export")
    async def export_report(asset_id: str, format: str = "json"):
        report = await usecase.export_asset_report(asset_id)

        if format == "csv":
            # Build CSV summary
            lines = ["scan_type,status,results,started_at,ended_at,job_id"]
            for s in report.get("scans", []):
                lines.append(
                    f'"{s["scan_type"]}","{s["status"]}","{s.get("results","") or 0}",'
                    f'"{s.get("started_at","") or ""}","{s.get("ended_at","") or ""}","{s["job_id"]}"'
                )
            csv_content = "\n".join(lines)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="easm-{asset_id[:8]}.csv"',
                    "Access-Control-Allow-Origin": "*",
                }
            )

        # Default: full JSON export
        json_str = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="easm-{asset_id[:8]}.json"',
                "Access-Control-Allow-Origin": "*",
            }
        )

    return router
