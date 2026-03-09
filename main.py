#!/usr/bin/env python3
# Host Scanner TUI - Integrated pipeline with subfinder + bugscanner-go + scan.py

import os
import sys
import subprocess
import shutil
import tempfile
import time
from datetime import datetime

# Warna ANSI
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

def cprint(msg, color=GREEN, end="\n"):
    print(f"{color}{msg}{RESET}", end=end)

def banner():
    cprint(r"""
 ####  ##  ##  ###       ###             ##
## ###  ####    ##       ##     ##  ## #####   ####
######   ##     ## ##### #####  ##  ##  ##    ## ##
##  ## ##  ##   ##       ##  ##  #####  ## ## ##
 ####  ##  ## ######     ######     ##  ###    #####
                                #####
    """, CYAN)
    cprint("       Subfinder to Scanner-go without Response", CYAN)
    cprint("       Github: github.com/kuhujiban1c/scanner", CYAN)
    print()

def check_dependency(tool):
    """Cek apakah tool ada di PATH"""
    if shutil.which(tool) is None:
        return False
    return True

def run_command(cmd, description=None):
    """Jalankan perintah dan tampilkan output real-time"""
    if description:
        cprint(f"[*] {description}", GREEN)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in process.stdout:
        print(f"    {line}", end="")
    process.wait()
    if process.returncode != 0:
        cprint(f"[!] Perintah gagal: {cmd}", RED)
        return False
    return True

def run_subfinder(domain, output_file):
    """Jalankan subfinder untuk domain, hasil disimpan di output_file"""
    cmd = f"subfinder -d {domain} -o {output_file} -silent"
    return run_command(cmd, f"Menjalankan subfinder untuk {domain}")

def run_bugscanner(input_file, output_file):
    """Jalankan bugscanner-go untuk memfilter domain live"""
    # Sesuaikan perintah dengan tool Anda. Contoh:
    cmd = f"bugscanner-go scan direct -f {input_file} -o {output_file}"
    return run_command(cmd, "Memfilter domain live dengan bugscanner-go")

# Gabungkan fungsi-fungsi HostResponse dari script sebelumnya
# (Kita salin kelas HostResponse, Agent, dll dari script yang sudah dibuat)
# Agar tidak terlalu panjang, kita impor? Tapi lebih baik disertakan langsung.
# Untuk hemat ruang, saya akan menyalin kode HostResponse dari versi sebelumnya,
# tetapi dengan sedikit modifikasi agar bisa dipanggil langsung.

# Kita perlu import modul yang digunakan
import re
import requests
import socket
import random
import ipaddress
import threading
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# Default user agents
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")
_file_lock = threading.Lock()

class HostResponse:
    # (semua method seperti sebelumnya, tapi kita perlu sesuaikan agar tidak bergantung pada file eksternal)
    def __init__(self, target, user_agent, proxy, result_file, ports=None, timeout=6, max_redirects=5):
        self.target = self._clean_domain(target)
        self.user_agent = user_agent
        self.proxy = proxy
        self.result_file = result_file
        self.ports = ports or [80, 443]
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = self._build_session()

    @staticmethod
    def _clean_domain(domain):
        domain = domain.strip()
        for prefix in ("https://", "http://"):
            if domain.lower().startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0].split("#")[0]
        return domain.rstrip(".").lower()

    @staticmethod
    def is_valid_domain(domain):
        return bool(DOMAIN_RE.match(domain))

    @staticmethod
    def is_ip_address(target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _build_session(self):
        s = requests.Session()
        s.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        s.max_redirects = self.max_redirects
        if self.proxy:
            s.proxies.update({"http": self.proxy, "https": self.proxy})
        s.verify = True
        return s

    def fetch_subdomains(self):
        subdomains = set()
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
                            if token.endswith(self.target) and self.is_valid_domain(token):
                                subdomains.add(token)
        except Exception as e:
            cprint(f"  [!] Subdomain fetch error: {e}", YELLOW)
        return sorted(subdomains)

    def get_headers(self, domain):
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                return resp.status_code, resp.headers.get("Server", "N/A")
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

    def check_port(self, domain, port):
        try:
            with socket.create_connection((domain, port), timeout=3):
                return True
        except:
            return False

    def scan_ports(self, domain):
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(10, len(self.ports))) as pool:
            futures = {pool.submit(self.check_port, domain, p): p for p in self.ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except:
                    pass
        return sorted(open_ports)

    def get_tls_info(self, domain):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    return tls.version()
        except:
            return "None"

    def resolve_ip(self, domain):
        if self.is_ip_address(domain):
            return domain
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            unique_ips = sorted({addr[4][0] for addr in ips})
            return ", ".join(unique_ips) if unique_ips else "N/A"
        except socket.gaierror:
            return "N/A"

    def check_domain(self, domain):
        domain = self._clean_domain(domain)
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

    def run(self):
        cprint(f"[*] Enumerating subdomains for: {self.target}")
        if self.is_ip_address(self.target):
            cprint("[*] Target is IP, skipping subdomain enumeration.")
            subdomains = [self.target]
        else:
            if not self.is_valid_domain(self.target):
                cprint(f"[!] Invalid domain format: {self.target}", RED)
                return []
            subdomains = self.fetch_subdomains()
            if not subdomains:
                cprint("[!] No subdomains found. Checking target directly...", YELLOW)
                subdomains = [self.target]
        cprint(f"[+] Found {len(subdomains)} unique target(s)\n")
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
                    cprint(f"  [!] Error checking {sd}: {e}", RED)
        self._save_results(results)
        if errors:
            cprint(f"[!] {errors} domain(s) had errors", YELLOW)
        self.session.close()
        return results

    def _save_results(self, results):
        if not results:
            return
        with _file_lock:
            with open(self.result_file, "a", encoding="utf-8") as f:
                f.write(f"# Scan: {self.target} — {datetime.now().isoformat()}\n")
                for line in sorted(results):
                    f.write(line + "\n")
        cprint(f"\n[+] {len(results)} result(s) saved to {self.result_file}", GREEN)

class Agent:
    def __init__(self, ua_file="user-agents.txt"):
        self.agents = self._load(ua_file)
    @staticmethod
    def _load(path):
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    agents = [line.strip() for line in f if line.strip()]
                if agents:
                    return agents
            except:
                pass
        return list(DEFAULT_USER_AGENTS)
    def random(self):
        return random.choice(self.agents)

# Fungsi untuk menjalankan scan.py pada file domain
def run_scan_on_file(input_file, output_file, proxy=None, ports="80,443", timeout=6):
    """Memproses file berisi daftar domain/IP dengan HostResponse"""
    if not os.path.isfile(input_file):
        cprint(f"[!] File tidak ditemukan: {input_file}", RED)
        return
    with open(input_file, "r") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not targets:
        cprint("[!] File kosong.", YELLOW)
        return
    # Parse ports
    port_list = []
    for p in ports.split(","):
        try:
            port_list.append(int(p.strip()))
        except:
            pass
    if not port_list:
        port_list = [80, 443]
    agent = Agent()
    all_results = []
    for target in targets:
        cprint(f"\n[→] Memindai: {target}", CYAN)
        ua = agent.random()
        checker = HostResponse(
            target=target,
            user_agent=ua,
            proxy=proxy,
            result_file=output_file,
            ports=port_list,
            timeout=timeout
        )
        results = checker.run()
        all_results.extend(results)
    cprint(f"\n[✓] Selesai. Total {len(all_results)} hasil di {output_file}", GREEN)

# Menu utama
def main_menu():
    while True:
        banner()
        cprint("Pilih menu:", CYAN)
        print("  1. Scan domain baru (subfinder → bugscanner → scan)")
        print("  2. Scan dari file domain (langsung scan)")
        print("  3. Keluar")
        choice = input("\nMasukkan pilihan [1/2/3]: ").strip()
        if choice == "1":
            domain = input("Masukkan domain target (contoh: example.com): ").strip()
            if not domain:
                cprint("[!] Domain tidak boleh kosong.", RED)
                continue
            output = input("Nama file output (default: hasil_<domain>.txt): ").strip()
            if not output:
                output = f"hasil_{domain}.txt"
            proxy = input("Proxy (opsional, kosongkan jika tidak): ").strip() or None
            ports = input("Ports to scan (default: 80,443): ").strip() or "80,443"
            timeout = input("Timeout (detik, default: 6): ").strip() or "6"
            try:
                timeout = int(timeout)
            except:
                timeout = 6

            # Cek dependensi
            if not check_dependency("subfinder"):
                cprint("[!] subfinder tidak ditemukan. Pastikan terinstall.", RED)
                continue
            if not check_dependency("bugscanner-go"):
                cprint("[!] bugscanner-go tidak ditemukan. Pastikan terinstall.", RED)
                # Tanya tetap lanjut?
                lanjut = input("Lanjutkan tanpa bugscanner? (y/n): ").strip().lower()
                if lanjut != 'y':
                    continue

            # Buat file sementara
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_sub, \
                 tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_live:
                sub_file = tmp_sub.name
                live_file = tmp_live.name

            try:
                # Langkah 1: subfinder
                if not run_subfinder(domain, sub_file):
                    cprint("[!] Gagal menjalankan subfinder.", RED)
                    continue

                # Langkah 2: bugscanner (jika ada)
                if check_dependency("bugscanner-go"):
                    if not run_bugscanner(sub_file, live_file):
                        cprint("[!] bugscanner-go gagal, gunakan hasil subfinder.", YELLOW)
                        # Jika gagal, pakai file subfinder sebagai live
                        import shutil
                        shutil.copy(sub_file, live_file)
                else:
                    # bugscanner tidak ada, gunakan subfinder langsung
                    import shutil
                    shutil.copy(sub_file, live_file)

                # Langkah 3: scan
                run_scan_on_file(live_file, output, proxy, ports, timeout)
            finally:
                # Hapus file sementara
                os.unlink(sub_file)
                os.unlink(live_file)

        elif choice == "2":
            file_path = input("Masukkan path file domain: ").strip()
            if not os.path.isfile(file_path):
                cprint("[!] File tidak ditemukan.", RED)
                continue
            output = input("Nama file output (default: result.txt): ").strip() or "result.txt"
            proxy = input("Proxy (opsional): ").strip() or None
            ports = input("Ports to scan (default: 80,443): ").strip() or "80,443"
            timeout = input("Timeout (detik, default: 6): ").strip() or "6"
            try:
                timeout = int(timeout)
            except:
                timeout = 6
            run_scan_on_file(file_path, output, proxy, ports, timeout)

        elif choice == "3":
            cprint("Terima kasih!", GREEN)
            sys.exit(0)
        else:
            cprint("[!] Pilihan tidak valid.", RED)
        input("\nTekan Enter untuk kembali ke menu...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        cprint("\n[!] Dibatalkan pengguna.", YELLOW)
        sys.exit(0)
