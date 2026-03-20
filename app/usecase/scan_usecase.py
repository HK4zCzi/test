import asyncio, logging
from fastapi import HTTPException
from app.domain.scan import ScanType, DOMAIN_ONLY_SCANS, IP_ONLY_SCANS
from app.repository.scan_repository import ScanRepository
from app.repository.asset_repository import AssetRepository

logger = logging.getLogger(__name__)

SCAN_GROUPS = {
    ScanType.passive_all: {
        "domain": [
            ScanType.dns, ScanType.whois, ScanType.cert_trans, ScanType.ssl,
            ScanType.tech, ScanType.headers, ScanType.waf, ScanType.virustotal,
            ScanType.urlscan, ScanType.http_probe,
        ],
        "ip": [
            ScanType.ip, ScanType.asn, ScanType.reverse_dns, ScanType.shodan,
        ],
    },
    ScanType.domain_full: {
        "domain": [
            ScanType.dns, ScanType.whois, ScanType.subdomain, ScanType.cert_trans,
            ScanType.ssl, ScanType.tech, ScanType.headers, ScanType.waf,
            ScanType.takeover, ScanType.http_probe, ScanType.gau,
            ScanType.virustotal, ScanType.urlscan, ScanType.js_scan,
            ScanType.cors, ScanType.s3, ScanType.dir_brute,
            ScanType.xss, ScanType.ssrf, ScanType.crlf,
        ],
        "ip": [],
    },
    ScanType.ip_full: {
        "domain": [],
        "ip": [
            ScanType.ip, ScanType.asn, ScanType.reverse_dns,
            ScanType.shodan, ScanType.port,
        ],
    },
    ScanType.all: {
        "domain": [
            ScanType.dns, ScanType.whois, ScanType.subdomain, ScanType.cert_trans,
            ScanType.ssl, ScanType.tech, ScanType.headers, ScanType.waf,
            ScanType.takeover, ScanType.http_probe, ScanType.gau,
            ScanType.virustotal, ScanType.urlscan, ScanType.js_scan,
            ScanType.cors, ScanType.s3, ScanType.dir_brute,
        ],
        "ip": [
            ScanType.ip, ScanType.asn, ScanType.reverse_dns,
            ScanType.shodan, ScanType.port,
        ],
    },
}

DISPATCH_MAP = {
    ScanType.dns:         ("DNSScanner",        "scan"),
    ScanType.whois:       ("WHOISScanner",       "scan"),
    ScanType.subdomain:   ("SubdomainScanner",   "scan"),
    ScanType.cert_trans:  ("CertTransScanner",   "scan"),
    ScanType.ssl:         ("SSLScanner",         "scan"),
    ScanType.tech:        ("TechScanner",        "scan"),
    ScanType.headers:     ("HeadersScanner",     "scan"),
    ScanType.waf:         ("WAFScanner",         "scan"),
    ScanType.takeover:    ("TakeoverScanner",    "scan"),
    ScanType.ip:          ("IPScanner",          "scan"),
    ScanType.asn:         ("ShodanScanner",      "scan"),  # ASN via BGPView in Shodan scanner
    ScanType.reverse_dns: ("IPScanner",          "scan"),
    ScanType.shodan:      ("ShodanScanner",      "scan"),
    ScanType.port:        ("PortScanner",        "scan"),
    ScanType.http_probe:  ("HTTPProbeScanner",   "scan"),
    ScanType.gau:         ("GAUScanner",         "scan"),
    ScanType.virustotal:  ("VirusTotalScanner",  "scan"),
    ScanType.urlscan:     ("URLScanScanner",     "scan"),
    ScanType.cors:        ("CORSScanner",        "scan"),
    ScanType.s3:          ("S3Scanner",          "scan"),
    ScanType.js_scan:     ("JSScanner",          "scan"),
    ScanType.dir_brute:   ("DirScanner",         "scan"),
    ScanType.xss:         ("XSSScanner",         "scan"),
    ScanType.ssrf:        ("SSRFScanner",         "scan"),
    ScanType.crlf:        ("CRLFScanner",         "scan"),
}


def _is_compatible(stype: ScanType, asset_type: str) -> bool:
    """
    Clear rules:
    - Domain-only scans require asset_type == 'domain'
    - IP-only scans require asset_type == 'ip'
    - service assets can do http_probe, headers, ssl, tech, waf
    - Groups are handled separately
    """
    if stype in SCAN_GROUPS:
        return True  # groups always allowed — filtered per asset type internally

    if stype in DOMAIN_ONLY_SCANS:
        if asset_type == "service":
            # Allow a subset for service assets
            return stype in {ScanType.http_probe, ScanType.headers, ScanType.ssl, ScanType.tech, ScanType.waf}
        return asset_type == "domain"

    if stype in IP_ONLY_SCANS:
        return asset_type == "ip"

    return True  # unknown types — allow through


class ScanUsecase:
    def __init__(self, scan_repo: ScanRepository, asset_repo: AssetRepository):
        self.scan_repo = scan_repo
        self.asset_repo = asset_repo

    async def start_scan(self, asset_id: str, scan_type: str) -> dict:
        asset = await self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(404, detail=f"Asset '{asset_id}' not found")

        try:
            stype = ScanType(scan_type)
        except ValueError:
            valid = [e.value for e in ScanType if e not in SCAN_GROUPS]
            raise HTTPException(400, detail=f"Invalid scan_type '{scan_type}'. Valid values: {valid}")

        asset_type = asset["type"]  # 'domain', 'ip', 'service'

        # Handle scan groups
        if stype in SCAN_GROUPS:
            group_def = SCAN_GROUPS[stype]
            subtypes = group_def.get(asset_type, [])
            # For 'all' group, combine both if somehow relevant
            if not subtypes:
                raise HTTPException(
                    400,
                    detail=f"Scan group '{scan_type}' has no scans for asset type '{asset_type}'. "
                           f"Use 'domain_full' for domains, 'ip_full' for IPs."
                )
            jobs = []
            for sub in subtypes:
                job = await self.scan_repo.create_job(asset_id, sub.value)
                asyncio.create_task(self._run(job["id"], asset["name"], sub))
                jobs.append(job)
            return {"group": scan_type, "asset_type": asset_type,
                    "jobs_started": len(jobs), "jobs": jobs}

        # Single scan — check compatibility
        if not _is_compatible(stype, asset_type):
            if stype in DOMAIN_ONLY_SCANS:
                raise HTTPException(400, detail=f"'{scan_type}' requires a domain asset (current: {asset_type})")
            if stype in IP_ONLY_SCANS:
                raise HTTPException(400, detail=f"'{scan_type}' requires an IP asset (current: {asset_type})")

        job = await self.scan_repo.create_job(asset_id, scan_type)
        asyncio.create_task(self._run(job["id"], asset["name"], stype))
        return job

    async def _run(self, job_id: str, target: str, stype: ScanType):
        await self.scan_repo.set_job_running(job_id)
        try:
            results = await asyncio.get_event_loop().run_in_executor(
                None, self._dispatch, target, stype
            )
            await self.scan_repo.save_results(job_id, results)
            await self.scan_repo.update_job_status(job_id, "completed", results_count=len(results))
            logger.info("✅ %s on %s → %d results", stype.value, target, len(results))
        except ValueError as e:
            await self.scan_repo.update_job_status(job_id, "failed", error=str(e))
            logger.warning("⚠️  %s on %s: %s", stype.value, target, e)
        except Exception as e:
            await self.scan_repo.update_job_status(job_id, "failed", error=str(e)[:300])
            logger.error("❌ %s on %s: %s", stype.value, target, e)

    def _dispatch(self, target: str, stype: ScanType) -> list[dict]:
        import app.scanner as scanners
        entry = DISPATCH_MAP.get(stype)
        if not entry:
            return [{"scan_type": stype.value, "target": target, "note": "not implemented"}]
        cls_name, method = entry
        instance = getattr(scanners, cls_name)()
        if stype == ScanType.port:
            return instance.scan(target, allow_public=True)
        return getattr(instance, method)(target)

    async def get_job(self, job_id: str) -> dict:
        job = await self.scan_repo.get_job(job_id)
        if not job:
            raise HTTPException(404, detail=f"Job {job_id} not found")
        return job

    async def get_results(self, job_id: str) -> dict:
        job = await self.scan_repo.get_job(job_id)
        if not job:
            raise HTTPException(404, detail=f"Job {job_id} not found")
        results = await self.scan_repo.get_results(job_id)
        return {"job_id": job_id, "scan_type": job["scan_type"],
                "status": job["status"], "results": results}

    async def list_scans_for_asset(self, asset_id: str) -> list[dict]:
        asset = await self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(404, detail=f"Asset {asset_id} not found")
        return await self.scan_repo.list_jobs_for_asset(asset_id)

    async def get_all_results_for_asset(self, asset_id: str) -> list[dict]:
        asset = await self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(404, detail=f"Asset {asset_id} not found")
        return await self.scan_repo.get_all_results_for_asset(asset_id)

    async def export_asset_report(self, asset_id: str) -> dict:
        """Export full scan report for one asset"""
        asset = await self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(404, detail=f"Asset {asset_id} not found")
        jobs = await self.scan_repo.list_jobs_for_asset(asset_id)
        scans = []
        for job in jobs:
            results = await self.scan_repo.get_results(job["id"])
            scans.append({
                "job_id":     job["id"],
                "scan_type":  job["scan_type"],
                "status":     job["status"],
                "started_at": job.get("started_at"),
                "ended_at":   job.get("ended_at"),
                "results":    results,
            })
        import datetime
        return {
            "asset":       asset,
            "exported_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_jobs":  len(jobs),
            "scans":       scans,
        }
