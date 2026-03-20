from pydantic import BaseModel
from enum import Enum
from typing import Optional, Any


class ScanType(str, Enum):
    # ── Passive domain ────────────────────────────────────────────
    dns         = "dns"
    whois       = "whois"
    subdomain   = "subdomain"
    cert_trans  = "cert_trans"
    ssl         = "ssl"
    tech        = "tech"
    headers     = "headers"
    waf         = "waf"
    takeover    = "takeover"
    gau         = "gau"
    virustotal  = "virustotal"
    urlscan     = "urlscan"
    js_scan     = "js_scan"
    cors        = "cors"
    s3          = "s3"
    dir_brute   = "dir_brute"
    http_probe  = "http_probe"
    xss         = "xss"
    ssrf        = "ssrf"
    crlf        = "crlf"
    # ── Passive IP ────────────────────────────────────────────────
    ip          = "ip"
    asn         = "asn"
    reverse_dns = "reverse_dns"
    shodan      = "shodan"
    # ── Active ────────────────────────────────────────────────────
    port        = "port"
    # ── Both (domain or IP) ───────────────────────────────────────
    virustotal_ip = "virustotal_ip"   # VT lookup for IP
    # ── Scan groups ───────────────────────────────────────────────
    passive_all  = "passive_all"
    domain_full  = "domain_full"
    ip_full      = "ip_full"
    all          = "all"


class ScanStatus(str, Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"
    partial   = "partial"


class ScanJob(BaseModel):
    id:         str
    asset_id:   str
    scan_type:  ScanType
    status:     ScanStatus = ScanStatus.pending
    started_at: Optional[str] = None
    ended_at:   Optional[str] = None
    error:      str = ""
    results:    int = 0
    created_at: str


# Strictly domain-only scans
DOMAIN_ONLY_SCANS = {
    ScanType.dns, ScanType.whois, ScanType.subdomain, ScanType.cert_trans,
    ScanType.ssl, ScanType.tech, ScanType.headers, ScanType.waf,
    ScanType.takeover, ScanType.virustotal, ScanType.gau, ScanType.urlscan,
    ScanType.js_scan, ScanType.cors, ScanType.s3, ScanType.dir_brute,
    ScanType.http_probe, ScanType.xss, ScanType.ssrf, ScanType.crlf,
}

# Strictly IP-only scans
IP_ONLY_SCANS = {
    ScanType.ip, ScanType.asn, ScanType.reverse_dns,
    ScanType.shodan, ScanType.port,
}

# Scans that work on both domain and IP
UNIVERSAL_SCANS = {
    ScanType.virustotal_ip,
}

# Keep these aliases for backward compatibility
PASSIVE_DOMAIN_SCANS = DOMAIN_ONLY_SCANS
PASSIVE_IP_SCANS = IP_ONLY_SCANS - {ScanType.port}
ACTIVE_SCANS = {ScanType.port}

# ── Vuln scan types (active) ──────────────────────────────────────
# These are already in ScanType via dir_brute etc., adding aliases here
