#!/usr/bin/env python3
"""
Standalone Scanner CLI
Can be used independently for direct scanning without pipeline
"""

import sys
from lib.logger_config import setup_logger
from lib.orchestrator import ScannerOrchestrator

logger = setup_logger(__name__)

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def cprint(msg: str, color: str = GREEN):
    """Print colored message."""
    print(f"{color}{msg}{RESET}")


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        cprint("Usage: python3 scan.py -f <file> -o <output> [options]", YELLOW)
        cprint("\nOptions:", CYAN)
        cprint("  -f, --file FILE        File with domains/IPs", GREEN)
        cprint("  -o, --output FILE      Output file (default: result.txt)", GREEN)
        cprint("  -p, --proxy URL        HTTP proxy URL", GREEN)
        cprint("  --ports PORTS          Ports (default: 80,443)", GREEN)
        cprint("  --timeout SEC          Timeout in seconds", GREEN)
        sys.exit(1)
    
    # Simple arg parsing
    args = {}
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] in ['-f', '--file'] and i + 1 < len(sys.argv):
            args['file'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] in ['-o', '--output'] and i + 1 < len(sys.argv):
            args['output'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] in ['-p', '--proxy'] and i + 1 < len(sys.argv):
            args['proxy'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--ports' and i + 1 < len(sys.argv):
            args['ports'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--timeout' and i + 1 < len(sys.argv):
            args['timeout'] = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    if 'file' not in args:
        cprint("[!] File is required (-f)", RED)
        sys.exit(1)
    
    # Parse ports
    ports_str = args.get('ports', '80,443')
    try:
        ports = [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        cprint(f"[!] Invalid ports: {ports_str}", RED)
        sys.exit(1)
    
    # Run scan
    orchestrator = ScannerOrchestrator(
        use_bugscanner=False,  # Don't use pipeline in standalone mode
        timeout=args.get('timeout', 6)
    )
    
    try:
        total = orchestrator.scan_file(
            args['file'],
            args.get('output', 'result.txt'),
            args.get('proxy'),
            ports
        )
        cprint(f"\n[✓] Scan complete. {total} result(s) saved.", GREEN)
    except Exception as e:
        cprint(f"[!] Error: {e}", RED)
        logger.exception("Error:")
        sys.exit(1)


if __name__ == "__main__":
    main()
