"""
S3 Bucket Scanner — enum common bucket names for a domain
Passive: HTTP HEAD requests to known S3 URL patterns
"""
import urllib.request
import urllib.error
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Bucket name patterns to test
BUCKET_PATTERNS = [
    "{domain}", "{domain}-backup", "{domain}-dev", "{domain}-staging",
    "{domain}-prod", "{domain}-assets", "{domain}-media", "{domain}-static",
    "{domain}-uploads", "{domain}-files", "{domain}-data", "{domain}-logs",
    "{domain}-public", "{domain}-private", "backup-{domain}", "dev-{domain}",
    "static-{domain}", "assets-{domain}", "media-{domain}", "files-{domain}",
    "{name}", "{name}-backup", "{name}-assets", "{name}-static",
    "{name}-dev", "{name}-prod", "{name}-staging", "{name}-media",
]

S3_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]


def _test_bucket(bucket_name: str) -> dict | None:
    """Test if S3 bucket exists and its access level"""
    urls_to_try = [
        f"https://{bucket_name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket_name}/",
    ]
    for url in urls_to_try:
        try:
            req = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"},
            )
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                return {
                    "bucket": bucket_name,
                    "url": url,
                    "status": resp.status,
                    "access": "public",
                    "severity": "high",
                    "note": "Publicly accessible S3 bucket",
                }
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    return {
                        "bucket": bucket_name,
                        "url": url,
                        "status": 403,
                        "access": "private",
                        "severity": "info",
                        "note": "Bucket exists but access denied",
                    }
                elif e.code == 404:
                    pass  # Doesn't exist
        except Exception:
            pass
    return None


class S3Scanner:
    """S3 bucket enumeration"""

    def scan(self, domain: str) -> list[dict]:
        # Extract name parts
        name = domain.split(".")[0]
        parts = domain.replace(".", "-")

        # Generate bucket name candidates
        candidates = set()
        for pattern in BUCKET_PATTERNS:
            candidates.add(pattern.format(domain=parts, name=name))
            candidates.add(pattern.format(domain=name, name=name))

        found = []
        public_buckets = []

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_test_bucket, b): b for b in candidates}
            for future in as_completed(futures, timeout=30):
                try:
                    r = future.result()
                    if r:
                        found.append(r)
                        if r["access"] == "public":
                            public_buckets.append(r["bucket"])
                except Exception:
                    pass

        result = {
            "domain":          domain,
            "buckets_tested":  len(candidates),
            "buckets_found":   len(found),
            "public_buckets":  public_buckets,
            "risk":            "high" if public_buckets else ("medium" if found else "low"),
            "findings":        sorted(found, key=lambda x: x["severity"]),
            "created_at":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
