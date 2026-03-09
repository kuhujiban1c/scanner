"""
Host Response Checker - Core scanning module
Consolidated from main.py and scan.py, with fixes and improvements
"""

import ssl
import re
import requests
import socket
import random
import os
import threading
import ipaddress
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, List, Tuple
from lib.logger_config import setup_logger

logger = setup_logger(__name__)

# Default user agents fallback
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

# Regex for basic domain validation
DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# Thread lock for file writing
_file_lock = threading.Lock()


class HostResponse:
    """
    Host Response Checker - Performs comprehensive host scanning
    
    Capabilities:
    - Subdomain enumeration (via rapiddns.io)
    - HTTP/HTTPS status checking
    - Port scanning
    - TLS version detection
    - IP resolution
    """

    def __init__(
        self,
        target: str,
        user_agent: str,
        proxy: Optional[str] = None,
        result_file: str = "result.txt",
        ports: Optional[List[int]] = None,
        timeout: int = 6,
        max_redirects: int = 5,
    ):
        """
        Initialize HostResponse scanner
        
        Args:
            target: Domain or IP to scan
            user_agent: User agent string to use
            proxy: Optional proxy URL
            result_file: Output file path
            ports: List of ports to scan (default: [80, 443])
            timeout: HTTP request timeout in seconds
            max_redirects: Max HTTP redirects to follow
        """
        self.target = self._clean_domain(target)
        self.user_agent = user_agent
        self.proxy = proxy
        self.result_file = result_file
        self.ports = ports or [80, 443]
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = self._build_session()

    @staticmethod
    def _clean_domain(domain: str) -> str:
        """Strip protocol, path, query string, and trailing slashes from domain."""
        domain = domain.strip()
        for prefix in ("https://", "http://"):
            if domain.lower().startswith(prefix):
                domain = domain[len(prefix) :]
        # Remove path, query, fragment
        domain = domain.split("/")[0].split("?")[0].split("#")[0]
        return domain.rstrip(".").lower()

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Basic domain format validation."""
        return bool(DOMAIN_RE.match(domain))

    @staticmethod
    def is_ip_address(target: str) -> bool:
        """Check if target is an IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _build_session(self) -> requests.Session:
        """Reuse a single requests.Session for connection pooling."""
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )
        s.max_redirects = self.max_redirects
        if self.proxy:
            s.proxies.update({"http": self.proxy, "https": self.proxy})
        s.verify = True
        return s

    # ── Subdomain enumeration ──────────────────────────────────────
    def fetch_subdomains(self) -> List[str]:
        """Return a deduplicated list of subdomains from rapiddns.io."""
        subdomains: set = set()
        try:
            api = f"https://rapiddns.io/subdomain/{self.target}?full=1&down=0"
            resp = self.session.get(api, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            tbody = soup.find("tbody")
            if tbody:
                for row in tbody.find_all("tr"):
                    td = row.find("td")
                    if td:
                        for token in td.text.split():
                            token = token.strip().lower().rstrip(".")
                            if token.endswith(self.target) and self.is_valid_domain(
                                token
                            ):
                                subdomains.add(token)
        except requests.RequestException as e:
            logger.warning(f"Subdomain fetch error: {e}")
        return sorted(subdomains)

    # ── Per-domain checks ──────────────────────────────────────────
    def get_headers(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieve status code and server header.
        Tries HTTPS first, falls back to HTTP.
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=True
                )
                return (
                    str(resp.status_code),
                    resp.headers.get("Server", "N/A"),
                )
            except requests.exceptions.SSLError:
                if scheme == "https":
                    continue
                return None, None
            except requests.exceptions.TooManyRedirects:
                return "Redirect Loop", "N/A"
            except requests.RequestException as e:
                if scheme == "https":
                    continue
                logger.debug(f"Error checking {domain}: {e}")
                return None, None
        return None, None

    def check_port(self, domain: str, port: int) -> bool:
        """Return True if the TCP port is open."""
        try:
            with socket.create_connection((domain, port), timeout=3):
                return True
        except (socket.timeout, OSError, socket.gaierror):
            return False

    def scan_ports(self, domain: str) -> List[int]:
        """Scan multiple ports concurrently for a single domain."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(10, len(self.ports))) as pool:
            futures = {pool.submit(self.check_port, domain, p): p for p in self.ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")
        return sorted(open_ports)

    def get_tls_info(self, domain: str) -> str:
        """Return the negotiated TLS version."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    return tls.version()
        except Exception:
            return "None"

    def resolve_ip(self, domain: str) -> str:
        """Resolve domain to all IP addresses, or return IP directly."""
        if self.is_ip_address(domain):
            return domain
        try:
            ips = socket.getaddrinfo(
                domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            unique_ips = sorted({addr[4][0] for addr in ips})
            return ", ".join(unique_ips) if unique_ips else "N/A"
        except socket.gaierror:
            return "N/A"

    # ── Process a single domain ────────────────────────────────────
    def check_domain(self, domain: str) -> Optional[str]:
        """Run all checks and return minimal result line."""
        domain = self._clean_domain(domain)

        # Skip domain format validation if it's an IP address
        if not self.is_ip_address(domain) and not self.is_valid_domain(domain):
            return f"# {domain}|None|None||None|"

        ip = self.resolve_ip(domain)
        if ip == "N/A" and not self.is_ip_address(domain):
            return f"{domain}|None|None||None|"

        status, server = self.get_headers(domain)
        tls_version = self.get_tls_info(domain)
        open_ports = self.scan_ports(domain)
        open_ports_str = ",".join(str(p) for p in open_ports) if open_ports else ""

        status = status if status is not None else "None"
        server = server if server not in (None, "N/A") else "None"
        tls_version = "None" if tls_version in ("N/A", "None") else tls_version

        return f"{domain}|{status}|{server}|{open_ports_str}|{tls_version}|"

    # ── Save results (thread-safe) - RAW OUTPUT ONLY ───────────────
    def _save_results(self, results: List[str]) -> None:
        """
        Append results to file in raw format (NO HEADERS).
        Output format: domain|status|server|ports|tls_version|
        """
        if not results:
            return
        with _file_lock:
            try:
                with open(self.result_file, "a", encoding="utf-8") as f:
                    # ✅ ONLY WRITE RAW DATA - NO HEADER
                    for line in sorted(results):
                        f.write(line + "\n")
                logger.info(f"{len(results)} result(s) saved to {self.result_file}")
            except IOError as e:
                logger.error(f"Error writing results to {self.result_file}: {e}")

    # ── Main runner ────────────────────────────────────────────────
    def run(self) -> List[str]:
        """Enumerate subdomains (if domain) and check each one concurrently."""
        logger.info(f"Enumerating subdomains for: {self.target}")

        if self.is_ip_address(self.target):
            logger.info("Target is an IP address, skipping subdomain enumeration")
            subdomains = [self.target]
        else:
            if not self.is_valid_domain(self.target):
                logger.error(f"Invalid domain format: {self.target}")
                return []

            subdomains = self.fetch_subdomains()
            if not subdomains:
                logger.warning("No subdomains found. Checking target directly...")
                subdomains = [self.target]

        logger.info(f"Found {len(subdomains)} unique target(s)")

        results = []
        errors = 0
        workers = min(20, len(subdomains))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.check_domain, sd): sd for sd in subdomains}
            for future in as_completed(futures):
                sd = futures[future]
                try:
                    line = future.result()
                    if line:
                        logger.debug(f"Result: {line}")
                        results.append(line)
                except Exception as e:
                    errors += 1
                    logger.error(f"Error checking {sd}: {e}")

        self._save_results(results)

        if errors:
            logger.warning(f"{errors} domain(s) had errors during scan")

        self.session.close()
        return results


class Agent:
    """Provides a random User-Agent string with fallback support."""

    def __init__(self, ua_file: str = "user-agents.txt"):
        """
        Initialize Agent
        
        Args:
            ua_file: Path to file containing custom user agents (one per line)
        """
        self.agents = self._load(ua_file)

    @staticmethod
    def _load(path: str) -> List[str]:
        """Load user agents from file or use defaults."""
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    agents = [line.strip() for line in f if line.strip()]
                if agents:
                    logger.info(f"Loaded {len(agents)} custom user agents from {path}")
                    return agents
            except (IOError, UnicodeDecodeError) as e:
                logger.warning(f"Could not read {path}: {e}, using defaults")
        return list(DEFAULT_USER_AGENTS)

    def random(self) -> str:
        """Return a random user agent string."""
        return random.choice(self.agents)
