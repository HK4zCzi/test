"""
Port Scanner — dùng nmap (hoặc socket fallback)
Public IPs: cho phép với disclaimer rõ ràng
Private IPs: full scan không hạn chế
"""
import subprocess, socket, ipaddress, re, time, logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

SERVICE_MAP = {
    21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",
    80:"http",110:"pop3",143:"imap",443:"https",445:"smb",
    3306:"mysql",3389:"rdp",5432:"postgresql",6379:"redis",
    8080:"http-alt",8443:"https-alt",27017:"mongodb",
    9200:"elasticsearch",5000:"dev",8000:"dev",3000:"dev",
}


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _resolve_to_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def _nmap_scan(target: str, is_private: bool) -> list[dict]:
    """nmap scan — top 1000 ports for public, all common for private"""
    if is_private:
        args = ["nmap", "-sV", "-T4", "--open", "-oX", "-", target]
    else:
        # Public: top 100 ports, faster, polite timing
        args = ["nmap", "-sV", "-T3", "--open", "--top-ports", "100", "-oX", "-", target]

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if result.returncode == 0 and result.stdout:
            return _parse_nmap_xml(result.stdout)
    except subprocess.TimeoutExpired:
        logger.warning("nmap timeout for %s", target)
    except FileNotFoundError:
        pass
    return None  # signal to use fallback


def _parse_nmap_xml(xml: str) -> list[dict]:
    ports = []
    for proto, portid, block in re.findall(
        r'<port protocol="([^"]+)" portid="([^"]+)">(.*?)</port>', xml, re.DOTALL
    ):
        state_m   = re.search(r'<state state="([^"]+)"', block)
        service_m = re.search(r'<service name="([^"]*)"', block)
        product_m = re.search(r'product="([^"]*)"', block)
        ver_m     = re.search(r'version="([^"]*)"', block)
        extra_m   = re.search(r'extrainfo="([^"]*)"', block)
        if state_m and state_m.group(1) != "open":
            continue
        version = " ".join(filter(None, [
            product_m.group(1) if product_m else "",
            ver_m.group(1) if ver_m else "",
            extra_m.group(1) if extra_m else "",
        ])).strip()
        ports.append({
            "port":     int(portid),
            "protocol": proto,
            "state":    "open",
            "service":  service_m.group(1) if service_m else SERVICE_MAP.get(int(portid), "unknown"),
            "version":  version,
        })
    return sorted(ports, key=lambda x: x["port"])


def _socket_scan(target: str, ports_list: list[int]) -> list[dict]:
    open_ports = []
    def try_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            if s.connect_ex((target, port)) == 0:
                s.close()
                return {"port": port, "protocol": "tcp", "state": "open",
                        "service": SERVICE_MAP.get(port, "unknown"), "version": ""}
        except Exception:
            pass
        return None
    with ThreadPoolExecutor(max_workers=100) as ex:
        for r in as_completed([ex.submit(try_port, p) for p in ports_list]):
            result = r.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


class PortScanner:
    """
    Port scanner — nmap primary, socket fallback.
    Private IPs: full scan.
    Public IPs: top-100 ports, với disclaimer rõ ràng.
    """

    def scan(self, target: str, allow_public: bool = True) -> list[dict]:
        ip = _resolve_to_ip(target)
        is_private = _is_private_ip(ip)

        if not is_private and not allow_public:
            raise ValueError(
                f"Public IP scan disabled. Set allow_public=True or use private IPs only."
            )

        disclaimer = ""
        if not is_private:
            disclaimer = (
                "⚠️ Active scan on public IP. Only scan systems you own or have permission to test. "
                "Top-100 ports only for public IPs."
            )
            ports_list = list(SERVICE_MAP.keys()) + [8888, 9090, 9000, 4000, 4443, 2222]
        else:
            ports_list = list(SERVICE_MAP.keys())

        start = time.time()

        # Try nmap first
        open_ports = _nmap_scan(target, is_private)
        scanner_used = "nmap -sV"

        if open_ports is None:
            # Fallback to socket
            open_ports = _socket_scan(target if not is_private else ip, ports_list)
            scanner_used = "socket-fallback"

        duration_ms = int((time.time() - start) * 1000)

        result = {
            "target":           target,
            "ip_address":       ip,
            "is_private":       is_private,
            "open_ports":       open_ports,
            "closed_ports":     len(ports_list) - len(open_ports),
            "total_scanned":    len(ports_list),
            "scan_duration_ms": duration_ms,
            "scanner":          scanner_used,
            "disclaimer":       disclaimer,
            "created_at":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
