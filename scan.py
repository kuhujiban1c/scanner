#!/usr/bin/env python3
# Host Response Checker v2.1 - Enhanced & Minimal UI
# Original by Wannazid, modified by Assistant

import ssl
import re
import requests
import argparse
import socket
import random
import os
import sys
import threading
import ipaddress
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

# Default user agents fallback
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8888]

# Regex for basic domain validation
DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# Thread lock for file writing
_file_lock = threading.Lock()


class HostResponse:
    def __init__(
        self,
        target: str,
        user_agent: str,
        proxy: Optional[str],
        result_file: str = "result.txt",
        ports: Optional[list] = None,
        timeout: int = 6,
        max_redirects: int = 5,
    ):
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
    def fetch_subdomains(self) -> list:
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
            print(f"  [!] Subdomain fetch error: {e}")
        return sorted(subdomains)

    # ── Per-domain checks ──────────────────────────────────────────
    def get_headers(self, domain: str) -> tuple:
        """Retrieve status code, server header.
        Tries HTTPS first, falls back to HTTP."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=True
                )
                return (
                    resp.status_code,
                    resp.headers.get("Server", "N/A"),
                )
            except requests.exceptions.SSLError:
                if scheme == "https":
                    continue
                return None, None
            except requests.exceptions.TooManyRedirects:
                return "Redirect Loop", "N/A"
            except requests.RequestException:
                if scheme == "https":
                    continue
                return None, None
        return None, None

    def check_port(self, domain: str, port: int) -> bool:
        """Return True if the TCP port is open."""
        try:
            with socket.create_connection((domain, port), timeout=3):
                return True
        except (socket.timeout, OSError):
            return False

    def scan_ports(self, domain: str) -> list:
        """Scan multiple ports concurrently for a single domain."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(10, len(self.ports))) as pool:
            futures = {pool.submit(self.check_port, domain, p): p for p in self.ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass
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

    # ── Save results (thread-safe) ─────────────────────────────────
    def _save_results(self, results: list) -> None:
        """Append results to file in the same minimal format."""
        if not results:
            return
        with _file_lock:
            with open(self.result_file, "a", encoding="utf-8") as f:
                f.write(f"# Scan: {self.target} — {datetime.now().isoformat()}\n")
                for line in sorted(results):
                    f.write(line + "\n")
        print(f"\n  [+] {len(results)} result(s) saved to {self.result_file}")

    # ── Main runner ────────────────────────────────────────────────
    def run(self) -> list:
        """Enumerate subdomains (if domain) and check each one concurrently."""
        print(f"\n  [*] Enumerating subdomains for: {self.target}")

        if self.is_ip_address(self.target):
            print(f"  [*] Target is an IP address, skipping subdomain enumeration...")
            subdomains = [self.target]
        else:
            if not self.is_valid_domain(self.target):
                print(f"  [!] Invalid domain format: {self.target}")
                return []

            subdomains = self.fetch_subdomains()
            if not subdomains:
                print("  [!] No subdomains found. Checking target directly...")
                subdomains = [self.target]

        print(f"  [+] Found {len(subdomains)} unique target(s)\n")
        print(f"  {'─' * 60}")

        results = []
        errors = 0
        workers = min(20, len(subdomains))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(self.check_domain, sd): sd for sd in subdomains}
            for future in as_completed(future_map):
                sd = future_map[future]
                try:
                    line = future.result()
                    if line:
                        print(f"  [*] {line}")
                        results.append(line)
                except Exception as e:
                    errors += 1
                    print(f"  [!] Error checking {sd}: {e}")

        self._save_results(results)

        if errors:
            print(f"  [!] {errors} domain(s) had errors during scan")

        self.session.close()
        return results


class Agent:
    """Provides a random User-Agent string."""

    def __init__(self, ua_file: str = "user-agents.txt"):
        self.agents = self._load(ua_file)

    @staticmethod
    def _load(path: str) -> list:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    agents = [line.strip() for line in f if line.strip()]
                if agents:
                    return agents
            except (IOError, UnicodeDecodeError) as e:
                print(f"  [!] Warning: Could not read {path}: {e}")
        return list(DEFAULT_USER_AGENTS)

    def random(self) -> str:
        return random.choice(self.agents)


def build_banner(message: str, proxy_msg: str, result_file: str) -> str:
    return f"""
   __ __         __    ___                                
  / // /__  ___ / /_  / _ \\___ ___ ___  ___  ___  ___ ___ 
 / _  / _ \\(_-</ __/ / , _/ -_|_-</ _ \\/ _ \\/ _ \\(_-</ -_)
/_//_/\\___/___/\\__/ /_/|_|\\__/___/ .__/\\___/_//_/___/\\__/ 
                                /_/             V.2.1
    
         Owner  : Wannazid
         Github : github.com/wannazid
         Enhanced + Minimal UI

    [*] {message}
    [*] Proxy  : {proxy_msg}
    [*] Output : {result_file}
    [*] Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """


def parse_ports(port_str: str) -> list:
    """Parse comma-separated port string with validation."""
    ports = []
    for p in port_str.split(","):
        p = p.strip()
        if not p:
            continue
        val = int(p)
        if not (1 <= val <= 65535):
            raise ValueError(f"Port {val} out of range (1-65535)")
        ports.append(val)
    if not ports:
        raise ValueError("No valid ports specified")
    return ports


def main():
    parser = argparse.ArgumentParser(
        description="Host Response Checker v2.1 — Minimal output, supports IP addresses"
    )
    parser.add_argument(
        "-s", "--single", metavar="DOMAIN", type=str, help="Single target domain or IP"
    )
    parser.add_argument(
        "-m",
        "--multi",
        metavar="FILE",
        type=str,
        help="File containing multiple target domains/IPs",
    )
    parser.add_argument(
        "-r",
        "--result",
        metavar="FILE",
        type=str,
        default="result.txt",
        help="Output file (default: result.txt)",
    )
    parser.add_argument(
        "-p", "--proxy", metavar="URL", type=str, help="HTTP/HTTPS proxy URL"
    )
    parser.add_argument(
        "--ports",
        metavar="PORTS",
        type=str,
        default="80,443",
        help="Comma-separated ports to scan (default: 80,443)",
    )
    parser.add_argument(
        "--timeout",
        metavar="SEC",
        type=int,
        default=6,
        help="HTTP request timeout in seconds (default: 6)",
    )
    args = parser.parse_args()

    if not args.single and not args.multi:
        parser.print_help()
        sys.exit(1)

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid port list: {e}")
        sys.exit(1)

    message = f"Single target: {args.single}" if args.single else f"Multi target file: {args.multi}"
    proxy_msg = args.proxy if args.proxy else "None"

    print(build_banner(message, proxy_msg, args.result))

    agent = Agent()
    proxy = args.proxy or None

    targets = []
    if args.single:
        targets.append(args.single)
    elif args.multi:
        if not os.path.isfile(args.multi):
            print(f"[!] File not found: {args.multi}")
            sys.exit(1)
        try:
            with open(args.multi, "r", encoding="utf-8") as f:
                targets = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except (IOError, UnicodeDecodeError) as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)

    if not targets:
        print("[!] No targets specified.")
        sys.exit(1)

    total_results = 0
    for i, target in enumerate(targets, 1):
        print(f"\n  {'═' * 60}")
        print(f"  Target [{i}/{len(targets)}]: {target}")
        print(f"  {'═' * 60}")

        ua = agent.random()
        checker = HostResponse(
            target=target,
            user_agent=ua,
            proxy=proxy,
            result_file=args.result,
            ports=ports,
            timeout=args.timeout,
        )
        results = checker.run()
        total_results += len(results)

    print(f"\n  [✓] All scans complete. {total_results} total result(s) in: {args.result}\n")


if __name__ == "__main__":
    main()
