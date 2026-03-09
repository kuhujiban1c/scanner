"""
Scanner Orchestrator - Manages the scanning pipeline
Handles: subfinder → bugscanner → scan workflow
"""

import subprocess
import os
import tempfile
import shutil
from typing import Optional, List
from lib.logger_config import setup_logger
from lib.scanner import HostResponse, Agent

logger = setup_logger(__name__)


class ScannerOrchestrator:
    """
    Orchestrates the complete scanning pipeline
    
    Pipeline: subfinder → bugscanner (optional) → host response scanner
    """

    def __init__(self, use_bugscanner: bool = True, timeout: int = 6):
        """
        Initialize orchestrator
        
        Args:
            use_bugscanner: Whether to use bugscanner-go for filtering live domains
            timeout: HTTP request timeout
        """
        self.use_bugscanner = use_bugscanner
        self.timeout = timeout
        self.agent = Agent()

    @staticmethod
    def check_dependency(tool: str) -> bool:
        """Check if a tool exists in PATH."""
        return shutil.which(tool) is not None

    def run_command(self, cmd: str, description: Optional[str] = None) -> tuple:
        """
        Execute a shell command and return success status
        
        Args:
            cmd: Command to execute
            description: Description of what's being done
        
        Returns:
            Tuple of (success: bool, output: str)
        """
        if description:
            logger.info(description)
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error(f"Command failed: {cmd}")
                logger.error(f"Error: {result.stderr}")
                return False, result.stderr
            
            logger.debug(f"Command succeeded: {cmd}")
            return True, result.stdout
        
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {cmd}")
            return False, "Command timeout"
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, str(e)

    def run_subfinder(self, domain: str, output_file: str) -> bool:
        """
        Run subfinder for domain enumeration
        
        Args:
            domain: Target domain
            output_file: Output file path
        
        Returns:
            True if successful, False otherwise
        """
        if not self.check_dependency("subfinder"):
            logger.error("subfinder not found. Install it: https://github.com/projectdiscovery/subfinder")
            return False
        
        cmd = f"subfinder -d {domain} -o {output_file} -silent"
        success, _ = self.run_command(cmd, f"Running subfinder for {domain}")
        return success

    def run_bugscanner(self, input_file: str, output_file: str) -> bool:
        """
        Run bugscanner-go to filter live domains
        
        Args:
            input_file: Input file with domains
            output_file: Output file for live domains
        
        Returns:
            True if successful, False otherwise
        """
        if not self.check_dependency("bugscanner-go"):
            logger.warning("bugscanner-go not found. Skipping live domain filtering.")
            return False
        
        cmd = f"bugscanner-go scan direct -f {input_file} -o {output_file}"
        success, _ = self.run_command(cmd, "Filtering live domains with bugscanner-go")
        return success

    def scan_domain(self, domain: str, output_file: str, proxy: Optional[str] = None,
                    ports: Optional[List[int]] = None) -> int:
        """
        Full pipeline: subfinder → bugscanner → scan
        
        Args:
            domain: Target domain
            output_file: Output file for results
            proxy: Optional proxy URL
            ports: List of ports to scan
        
        Returns:
            Number of results found
        """
        if not domain:
            logger.error("Domain cannot be empty")
            return 0
        
        logger.info(f"Starting scan for domain: {domain}")
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_sub:
            sub_file = tmp_sub.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_live:
            live_file = tmp_live.name
        
        try:
            # Step 1: Run subfinder
            if not self.run_subfinder(domain, sub_file):
                logger.error("Failed to run subfinder")
                return 0
            
            # Step 2: Run bugscanner (if enabled and available)
            if self.use_bugscanner:
                if not self.run_bugscanner(sub_file, live_file):
                    logger.warning("bugscanner failed, using subfinder results directly")
                    shutil.copy(sub_file, live_file)
            else:
                shutil.copy(sub_file, live_file)
            
            # Step 3: Run host response scanner
            return self.scan_file(live_file, output_file, proxy, ports)
        
        finally:
            # Cleanup temporary files
            try:
                os.unlink(sub_file)
                os.unlink(live_file)
                logger.debug("Temporary files cleaned up")
            except OSError as e:
                logger.warning(f"Failed to cleanup temp files: {e}")

    def scan_file(self, file_path: str, output_file: str, proxy: Optional[str] = None,
                  ports: Optional[List[int]] = None) -> int:
        """
        Scan targets from a file
        
        Args:
            file_path: Path to file containing domains/IPs (one per line)
            output_file: Output file for results
            proxy: Optional proxy URL
            ports: List of ports to scan
        
        Returns:
            Number of results found
        """
        if not os.path.isfile(file_path):
            logger.error(f"File not found: {file_path}")
            return 0
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except (IOError, UnicodeDecodeError) as e:
            logger.error(f"Error reading file: {e}")
            return 0
        
        if not targets:
            logger.warning("No targets found in file")
            return 0
        
        logger.info(f"Found {len(targets)} target(s) to scan")
        
        if ports is None:
            ports = [80, 443]
        
        total_results = 0
        for i, target in enumerate(targets, 1):
            logger.info(f"Scanning [{i}/{len(targets)}]: {target}")
            
            ua = self.agent.random()
            checker = HostResponse(
                target=target,
                user_agent=ua,
                proxy=proxy,
                result_file=output_file,
                ports=ports,
                timeout=self.timeout
            )
            
            results = checker.run()
            total_results += len(results)
        
        logger.info(f"Scanning complete. Total {total_results} result(s) in {output_file}")
        return total_results
