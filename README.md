# 🔍 EASM — External Attack Surface Management

Hệ thống quản lý và quét bề mặt tấn công bên ngoài. Theo dõi, kiểm kê và tự động quét các tài sản kỹ thuật số (domain, IP, service) để phát hiện rủi ro bảo mật.

**Language:** Python 3.12 · **Framework:** FastAPI · **DB:** PostgreSQL 16 · **Arch:** Clean Architecture

---

## Mục lục
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
- [Chức năng](#chức-năng)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt và chạy](#cài-đặt-và-chạy)
- [Cấu trúc thư mục](#cấu-trúc-thư-mục)
- [API Reference](#api-reference)
- [Biến môi trường](#biến-môi-trường)
- [Chạy tests](#chạy-tests)
- [CI/CD](#cicd)

---

## Kiến trúc hệ thống

```
┌──────────────────────────────────────────────────────────────┐
│                      EASM Platform                           │
│                                                              │
│  ┌──────────────────┐      ┌──────────────────────────────┐ │
│  │  Frontend :3000  │─────▶│   FastAPI Backend :8080      │ │
│  │  (Nginx + HTML)  │      │   /assets  /scan-jobs        │ │
│  └──────────────────┘      │   /health  /docs (Swagger)   │ │
│                             └────────────────┬─────────────┘ │
│                                              │               │
│  ┌───────────────────────────────────────────▼────────────┐  │
│  │                  Scanner Engine (21 loại)               │  │
│  │                                                         │  │
│  │  PASSIVE DOMAIN         PASSIVE IP        ACTIVE        │  │
│  │  dns  whois  ssl        ip  asn  shodan   port (nmap)   │  │
│  │  waf  headers  tech     reverse_dns       xss  ssrf     │  │
│  │  subdomain  cert_trans                    crlf           │  │
│  │  gau  virustotal  cors                                   │  │
│  │  s3  dir_brute  js_scan  http_probe ...                  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  PostgreSQL :5432                                    │   │
│  │  assets | scan_jobs | scan_results (JSONB)           │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Clean Architecture — 4 layers tách biệt

```
HTTP Request
    ↓
Handler  (FastAPI routes)        ← app/handler/
    ↓
Usecase  (business logic)        ← app/usecase/
    ↓
Repository (DB queries)          ← app/repository/
    ↓
PostgreSQL  (asyncpg pool)       ← pkg/database.py

Scanner chạy async background task → lưu kết quả JSONB vào scan_results
```

---

## Chức năng

### Quản lý Assets
- Thêm / xóa / tìm kiếm assets (domain, IP, service)
- Phân trang, lọc theo type/status
- Batch create (trong 1 transaction), batch delete
- Thống kê tổng quan

### 21 Loại Scan

#### Passive Domain — an toàn, không cần permission
| Scan | Mô tả | Nguồn dữ liệu |
|------|-------|---------------|
| `dns` | A, AAAA, MX, NS, TXT, SPF, DMARC | dnspython + dig |
| `whois` | Registrar, ngày hết hạn, nameservers | python-whois |
| `subdomain` | Brute-force DNS 100 subdomains phổ biến | DNS resolver |
| `cert_trans` | Subdomains qua Certificate Transparency | crt.sh |
| `ssl` | Cert validity, TLS grade A–F, cipher, SANs | Python ssl |
| `tech` | Server, framework, CDN, CMS detection | HTTP headers + HTML |
| `headers` | Security headers audit, grade A–D | HTTP |
| `waf` | WAF detection + quét toàn subdomains | wafw00f + headers |
| `takeover` | Subdomain takeover — dangling CNAME | DNS + fingerprints |
| `gau` | GetAllURLs — Wayback, OTX, HackerTarget | Public APIs |
| `virustotal` | Domain reputation + OTX threat intel | VT API + OTX |
| `urlscan` | Passive scans, screenshots | urlscan.io |
| `js_scan` | JS files — endpoints + API key leak | HTTP + regex |
| `cors` | CORS misconfiguration check | HTTP OPTIONS |
| `s3` | S3 bucket enumeration | HEAD requests |
| `dir_brute` | Common paths/files brute-force | HTTP |
| `http_probe` | Alive check, redirect chain, title | requests |

#### Passive IP
| Scan | Mô tả | Nguồn |
|------|-------|-------|
| `ip` | Geolocation — country, city, ISP | ipapi.co / ipinfo.io |
| `asn` | BGP ASN number, prefix, org | BGPView free API |
| `reverse_dns` | PTR record | dig |
| `shodan` | Open ports, CVEs từ internet scan | Shodan API / HackerTarget |

#### Active Scans — chỉ dùng trên hệ thống bạn sở hữu
| Scan | Mô tả |
|------|-------|
| `port` | TCP port scan, service/version detection (nmap -sV) |
| `xss` | Reflected XSS với test payloads |
| `ssrf` | Server-Side Request Forgery check |
| `crlf` | CRLF header injection check |

#### Scan Groups — chạy song song
| Group | Scans |
|-------|-------|
| `domain_full` | Tất cả 20 domain scans song song |
| `ip_full` | ip + asn + reverse_dns + shodan + port |
| `passive_all` | Tất cả passive scans an toàn |
| `all` | Tất cả scans phù hợp asset type |

### Export
- **JSON** — toàn bộ raw scan results của 1 asset (tự động download)
- **CSV** — summary table tất cả jobs

---

## Yêu cầu hệ thống

| Tool | Version | Kiểm tra |
|------|---------|----------|
| Docker | 24+ | `docker --version` |
| Docker Compose plugin | 2+ | `docker compose version` |
| Python (chỉ local dev) | 3.10+ | `python3 --version` |

---

## Cài đặt và chạy

### Cách 1 — Docker Compose (khuyến nghị)

```bash
# 1. Clone repo
git clone https://github.com/HK4zCzi/dev.git
cd dev
git checkout homework

# 2. Cấu hình biến môi trường (tùy chọn)
cp .env.example .env
# Thêm API keys vào .env nếu muốn

# 3. Build và chạy toàn bộ stack
docker compose up --build -d

# 4. Kiểm tra
docker compose ps
docker compose logs backend --tail 20
```

Kết quả mong đợi:
```
NAME            STATUS    PORTS
easm-db         healthy   0.0.0.0:5432->5432/tcp
easm-backend    healthy   0.0.0.0:8080->8080/tcp
easm-frontend   running   0.0.0.0:3000->80/tcp
```

Truy cập:
| | URL |
|-|-----|
| **Web UI** | http://localhost:3000 |
| **API** | http://localhost:8080 |
| **Swagger** | http://localhost:8080/docs |
| **Health** | http://localhost:8080/health |

### Cách 2 — Local Development

```bash
# Start chỉ DB
docker compose up -d db

# Cài dependencies
pip install -r requirements.txt

# Chạy backend hot-reload
uvicorn main:app --reload --port 8080

# Frontend: mở frontend/index.html trong browser
```

### Dừng

```bash
docker compose down        # giữ data
docker compose down -v     # xóa data DB
```

---

## Cấu trúc thư mục

```
dev/
├── main.py                      # Entrypoint — CORS, lifespan, DI wiring
├── requirements.txt
├── Dockerfile                   # python:3.12-slim + nmap + wafw00f
├── Dockerfile.frontend          # nginx:alpine
├── docker-compose.yml
├── .env.example                 # Template env vars
│
├── app/
│   ├── domain/
│   │   ├── asset.py             # Asset entity, AssetType, AssetStatus enums
│   │   └── scan.py              # ScanType enum, sets, ScanJob model
│   ├── repository/              # SQL queries với asyncpg (parameterized)
│   ├── usecase/                 # Business logic, validation, dispatch
│   ├── handler/                 # FastAPI routes (assets + scans)
│   └── scanner/                 # 21 scanner modules
│
├── pkg/database.py              # asyncpg pool, exponential retry, migration
├── frontend/index.html          # SPA: Dashboard / Assets / Scanner / Results
│
├── tests/
│   ├── test_models.py           # Asset model validation
│   ├── test_scanners.py         # Scanner integration tests
│   └── test_scanners_unit.py    # Unit tests với mock
│
├── .github/workflows/ci.yml     # pytest + bandit + gitleaks + trivy
├── deploy_aws.sh                # EC2 auto-deploy script
├── setup_https.sh               # Let's Encrypt HTTPS setup
└── nginx/nginx.conf             # Production reverse proxy
```

---

## API Reference

### Assets
```
GET    /assets/stats
GET    /assets/count?type=domain&status=active
GET    /assets?page=1&limit=20&type=domain
GET    /assets/search?q=example
GET    /assets/{id}
POST   /assets/single          body: {"name":"example.com","type":"domain"}
POST   /assets/batch           body: {"assets":[...]}
DELETE /assets/batch?ids=id1,id2
```

### Scan
```
POST   /assets/{id}/scan           body: {"scan_type":"dns"}
GET    /scan-jobs/{job_id}
GET    /scan-jobs/{job_id}/results
GET    /assets/{id}/scans
GET    /assets/{id}/results
GET    /assets/{id}/export
GET    /assets/{id}/export?format=csv
```

### Scan types theo asset type
| Asset type | Scan types |
|------------|-----------|
| `domain` | dns, whois, subdomain, cert_trans, ssl, tech, headers, waf, takeover, gau, virustotal, urlscan, js_scan, cors, s3, dir_brute, http_probe, xss, ssrf, crlf, **domain_full**, passive_all, all |
| `ip` | ip, asn, reverse_dns, shodan, port, **ip_full**, passive_all, all |
| `service` | http_probe, headers, ssl, tech, waf |

---

## Biến môi trường

Tạo file `.env` (không commit lên Git):

```bash
# Bắt buộc
DATABASE_URL=postgresql://user:password@db:5432/assets_db

# Tùy chọn — không có vẫn chạy, dùng free API fallback tự động
VT_API_KEY=        # virustotal.com  — free 500 req/day
SHODAN_API_KEY=    # shodan.io       — free tier
URLSCAN_API_KEY=   # urlscan.io      — free tier
```

---

## Chạy tests

```bash
pip install -r requirements.txt

# Unit tests
pytest tests/ -v

# Coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Test compatibility (cần server đang chạy ở :8080)
python3 test_compatibility.py

# Test 20 scanners thực tế với youtube.com
python3 test_scanners.py
```

---

## CI/CD

GitHub Actions tự động chạy khi push hoặc tạo PR vào `main`:

| Job | Tool | Mô tả |
|-----|------|-------|
| `test` | pytest + coverage | Unit tests — các job sau phụ thuộc job này |
| `security-bandit` | bandit | Static analysis tìm lỗi bảo mật Python |
| `security-gitleaks` | gitleaks | Scan git history tìm secrets/keys bị lộ |
| `docker-build` | trivy | Build image + scan CVE HIGH/CRITICAL |

Xem tại: `https://github.com/HK4zCzi/dev/actions`
