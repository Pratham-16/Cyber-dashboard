import socket
import sys
import threading
import ipaddress
from queue import Queue

try:
    import requests
except ImportError:
    requests = None

# A broader, more realistic set of commonly-targeted ports than the original 8.
# Grouped loosely by category for readability if you want to trim this later.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017
]

# Friendly service names for the ports above, so output is more useful than just a number.
SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 135: 'MS-RPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP (submission)',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle DB', 1723: 'PPTP',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8000: 'HTTP-alt', 8080: 'HTTP-proxy', 8443: 'HTTPS-alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
}

TIMEOUT = 1.0
THREAD_COUNT = 30
lock = threading.Lock()
open_ports = []

# Hardcoded fallback in case the live fetch fails (offline, blocked, etc.) —
# Cloudflare's published ranges as of early 2026. These change rarely.
CLOUDFLARE_RANGES_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]


def get_cloudflare_ranges():
    """Fetch Cloudflare's current published IP ranges. Falls back to a
    hardcoded list if the request fails OR returns something that doesn't
    actually look like a list of CIDR ranges (e.g. a network block page)."""
    if requests is None:
        return CLOUDFLARE_RANGES_FALLBACK
    try:
        resp = requests.get("https://www.cloudflare.com/ips-v4", timeout=5)
        lines = [line.strip() for line in resp.text.splitlines() if line.strip()]

        # Validate every line actually parses as a CIDR network before trusting
        # the whole list — a proxy/firewall denial page would fail this check
        # and correctly fall back instead of silently matching nothing.
        valid_ranges = []
        for line in lines:
            try:
                ipaddress.ip_network(line)
                valid_ranges.append(line)
            except ValueError:
                return CLOUDFLARE_RANGES_FALLBACK  # not a real CIDR list, bail out

        return valid_ranges if valid_ranges else CLOUDFLARE_RANGES_FALLBACK
    except Exception:
        return CLOUDFLARE_RANGES_FALLBACK


def detect_cdn_proxy(ip):
    """Checks if the target IP belongs to a known CDN/proxy network (currently
    Cloudflare). Returns the CDN name if matched, otherwise None. This matters
    because scanning a CDN-fronted IP shows the CDN edge's open ports, not the
    real origin server's — the results can be misleading without this note."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for cidr in get_cloudflare_ranges():
        try:
            if ip_obj in ipaddress.ip_network(cidr):
                return "Cloudflare"
        except ValueError:
            continue
    return None


def grab_banner(ip, port, sock):
    """Try to read a short banner from the open port. Best-effort — many
    services won't send anything until spoken to first, which is fine."""
    try:
        sock.settimeout(0.8)
        banner = sock.recv(128).decode(errors='ignore').strip()
        # Collapse to one line and cap length so output stays readable
        banner = banner.replace('\r', ' ').replace('\n', ' ')[:80]
        return banner if banner else None
    except Exception:
        return None


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = SERVICE_NAMES.get(port, 'Unknown')
            banner = grab_banner(ip, port, sock)
            with lock:
                open_ports.append((port, service, banner))
    except Exception:
        pass
    finally:
        sock.close()


def worker(ip, queue):
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port)
        queue.task_done()


def main():
    if len(sys.argv) < 2:
        print("Error: No target IP/host provided")
        sys.exit(1)

    target = sys.argv[1]

    # Resolve hostname to IP up front, so we scan a real address and can report
    # a clear error immediately if the host doesn't resolve at all.
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Could not resolve host '{target}'")
        sys.exit(1)

    print(f"Target: {target} ({ip})")
    print(f"Ports Scanned: {len(DEFAULT_PORTS)}")

    cdn = detect_cdn_proxy(ip)
    if cdn:
        print(f"Warning: {ip} belongs to {cdn}'s network — this target is behind a CDN/proxy. "
              f"Open ports below reflect {cdn}'s edge server, NOT the real origin server.")

    queue = Queue()
    for port in DEFAULT_PORTS:
        queue.put(port)

    threads = []
    for _ in range(min(THREAD_COUNT, len(DEFAULT_PORTS))):
        t = threading.Thread(target=worker, args=(ip, queue))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()

    if not open_ports:
        print("Result: No open ports found among the scanned list.")
        return

    for port, service, banner in sorted(open_ports):
        line = f"Port {port} ({service}): OPEN"
        if banner:
            line += f" — {banner}"
        print(line)


if __name__ == "__main__":
    main()