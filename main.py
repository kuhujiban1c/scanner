#!/usr/bin/env python3
"""
Scanner CLI - Simple interactive tool for host scanning
Refactored version with improved structure and error handling
"""

import os
import sys
import argparse
from lib.logger_config import setup_logger
from lib.orchestrator import ScannerOrchestrator

logger = setup_logger(__name__)

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


def cprint(msg: str, color: str = GREEN, end: str = "\n"):
    """Print colored message."""
    print(f"{color}{msg}{RESET}", end=end)


def banner():
    """Display application banner."""
    cprint(r"""
 ####  ##  ##  ###       ###             ##
## ###  ####    ##       ##     ##  ## #####   ####
######   ##     ## ##### #####  ##  ##  ##    ## ##
##  ## ##  ##   ##       ##  ##  #####  ## ## ##
 ####  ##  ## ######     ######     ##  ###    #####
                                #####
    """, CYAN)
    cprint("       Scanner CLI - Host Discovery & Vulnerability Scanner", CYAN)
    cprint("       Github: github.com/kuhujiban1c/scanner", CYAN)
    print()


def interactive_menu():
    """Interactive menu mode."""
    orchestrator = ScannerOrchestrator()
    
    while True:
        banner()
        cprint("Select mode:", CYAN)
        print("  1. Scan single domain (subfinder → bugscanner → scan)")
        print("  2. Scan from file (direct scan)")
        print("  3. Exit")
        
        choice = input("\nEnter choice [1/2/3]: ").strip()
        
        if choice == "1":
            domain = input("Enter target domain (example: example.com): ").strip()
            if not domain:
                cprint("[!] Domain cannot be empty", RED)
                continue
            
            output = input("Output file name (default: hasil_<domain>.txt): ").strip()
            if not output:
                output = f"hasil_{domain}.txt"
            
            proxy = input("Proxy (optional, press Enter to skip): ").strip() or None
            ports_input = input("Ports to scan (default: 80,443): ").strip() or "80,443"
            
            try:
                ports = [int(p.strip()) for p in ports_input.split(",")]
            except ValueError:
                cprint("[!] Invalid port format", RED)
                continue
            
            timeout_input = input("Timeout in seconds (default: 6): ").strip() or "6"
            try:
                timeout = int(timeout_input)
            except ValueError:
                timeout = 6
            
            # Check dependencies
            if not orchestrator.check_dependency("subfinder"):
                cprint("[!] subfinder not found. Please install it.", RED)
                cprint("    https://github.com/projectdiscovery/subfinder", YELLOW)
                continue
            
            use_bugscanner = orchestrator.check_dependency("bugscanner-go")
            if not use_bugscanner:
                cprint("[!] bugscanner-go not found (optional)", YELLOW)
                proceed = input("Continue without bugscanner filtering? (y/n): ").strip().lower()
                if proceed != 'y':
                    continue
            
            orchestrator.use_bugscanner = use_bugscanner
            orchestrator.timeout = timeout
            
            try:
                total = orchestrator.scan_domain(domain, output, proxy, ports)
                cprint(f"\n[✓] Scan complete. {total} result(s) saved.", GREEN)
            except Exception as e:
                cprint(f"[!] Error during scan: {e}", RED)
                logger.exception("Scan error:")
        
        elif choice == "2":
            file_path = input("Enter file path with domains: ").strip()
            if not os.path.isfile(file_path):
                cprint(f"[!] File not found: {file_path}", RED)
                continue
            
            output = input("Output file name (default: result.txt): ").strip() or "result.txt"
            proxy = input("Proxy (optional, press Enter to skip): ").strip() or None
            ports_input = input("Ports to scan (default: 80,443): ").strip() or "80,443"
            
            try:
                ports = [int(p.strip()) for p in ports_input.split(",")]
            except ValueError:
                cprint("[!] Invalid port format", RED)
                continue
            
            timeout_input = input("Timeout in seconds (default: 6): ").strip() or "6"
            try:
                timeout = int(timeout_input)
            except ValueError:
                timeout = 6
            
            orchestrator.timeout = timeout
            
            try:
                total = orchestrator.scan_file(file_path, output, proxy, ports)
                cprint(f"\n[✓] Scan complete. {total} result(s) saved.", GREEN)
            except Exception as e:
                cprint(f"[!] Error during scan: {e}", RED)
                logger.exception("Scan error:")
        
        elif choice == "3":
            cprint("Thank you!", GREEN)
            sys.exit(0)
        
        else:
            cprint("[!] Invalid choice", RED)
        
        input("\nPress Enter to continue...")


def cli_mode():
    """Command-line mode with arguments."""
    parser = argparse.ArgumentParser(
        description="Scanner CLI - Host Discovery & Vulnerability Scanner"
    )
    parser.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        type=str,
        help="Single target domain for full pipeline scan"
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        type=str,
        help="File containing domains/IPs (one per line) for direct scanning"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        type=str,
        default="result.txt",
        help="Output file (default: result.txt)"
    )
    parser.add_argument(
        "-p", "--proxy",
        metavar="URL",
        type=str,
        help="HTTP/HTTPS proxy URL"
    )
    parser.add_argument(
        "--ports",
        metavar="PORTS",
        type=str,
        default="80,443",
        help="Comma-separated ports (default: 80,443)"
    )
    parser.add_argument(
        "--timeout",
        metavar="SEC",
        type=int,
        default=6,
        help="HTTP timeout in seconds (default: 6)"
    )
    parser.add_argument(
        "--no-bugscanner",
        action="store_true",
        help="Disable bugscanner-go filtering"
    )
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        cprint("[!] Invalid port format", RED)
        sys.exit(1)
    
    orchestrator = ScannerOrchestrator(
        use_bugscanner=not args.no_bugscanner,
        timeout=args.timeout
    )
    
    try:
        if args.domain:
            logger.info(f"Scanning domain: {args.domain}")
            total = orchestrator.scan_domain(args.domain, args.output, args.proxy, ports)
            cprint(f"\n[✓] Scan complete. {total} result(s) saved to {args.output}", GREEN)
        
        elif args.file:
            logger.info(f"Scanning from file: {args.file}")
            total = orchestrator.scan_file(args.file, args.output, args.proxy, ports)
            cprint(f"\n[✓] Scan complete. {total} result(s) saved to {args.output}", GREEN)
        
        else:
            parser.print_help()
            sys.exit(1)
    
    except Exception as e:
        cprint(f"[!] Error: {e}", RED)
        logger.exception("Error during scan:")
        sys.exit(1)


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        # CLI mode
        cli_mode()
    else:
        # Interactive mode
        try:
            interactive_menu()
        except KeyboardInterrupt:
            cprint("\n[!] Cancelled by user", YELLOW)
            sys.exit(0)


if __name__ == "__main__":
    main()
