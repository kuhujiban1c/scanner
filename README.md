# Scanner CLI 🚀

A powerful Python-based CLI tool for automated subdomain discovery and host vulnerability scanning.

## Features ✨

- 🔍 **Subdomain Enumeration** - Using RapidDNS & Subfinder
- 🔗 **Live Domain Filtering** - Optional bugscanner-go integration
- 📊 **HTTP Response Checking** - Status codes, headers, server info
- 🔐 **TLS Detection** - SSL/TLS version identification
- 🎯 **Port Scanning** - Concurrent port checking
- 🌐 **IP Resolution** - DNS lookup with IPv4/IPv6 support
- 📝 **Logging** - Comprehensive logging system
- ⚡ **Concurrent Processing** - Multi-threaded scanning for speed

## Installation

### Prerequisites

- Python 3.8+
- `subfinder` (for subdomain enumeration)
- `bugscanner-go` (optional, for live domain filtering)

### Quick Install

```bash
git clone https://github.com/kuhujiban1c/scanner.git
cd scanner

# Install dependencies
pip install -r requirements.txt

# Install external tools
chmod +x install.sh
./install.sh
```

## Usage

### Interactive Mode

```bash
python3 main.py
```

Menu options:
1. **Scan single domain** - Full pipeline: subfinder → bugscanner → scan
2. **Scan from file** - Direct scanning of domains/IPs
3. **Exit**

### CLI Mode

#### Single domain scan
```bash
python3 main.py -d example.com -o results.txt
```

#### File-based scan
```bash
python3 main.py -f domains.txt -o results.txt
```

#### Standalone scanner
```bash
python3 scan.py -f domains.txt -o results.txt
```

### Options

```
-d, --domain DOMAIN       Target domain for full pipeline
-f, --file FILE          File with domains (one per line)
-o, --output FILE        Output file (default: result.txt)
-p, --proxy URL          HTTP proxy URL
--ports PORTS            Ports to scan (default: 80,443)
--timeout SEC            HTTP timeout in seconds (default: 6)
--no-bugscanner          Disable bugscanner-go filtering
```

## Output Format

Results are saved in pipe-separated format:

```
domain|http_status|server_header|open_ports|tls_version|
```

Example:
```
example.com|200|nginx|80,443|TLSv1.2|
sub.example.com|301|Apache|80,443|TLSv1.3|
```

## Project Structure

```
scanner/
├── lib/
│   ├── __init__.py              # Library initialization
│   ├── scanner.py               # Core scanning module
│   ├── orchestrator.py          # Pipeline orchestration
│   └── logger_config.py         # Logging configuration
├── main.py                      # CLI entry point
├── scan.py                      # Standalone scanner
├── install.sh                   # Installation script
├── requirements.txt             # Python dependencies
├── .env.example                 # Configuration template
└── README.md                    # This file
```

## Architecture

### Scanner Module (`lib/scanner.py`)
- **HostResponse**: Main scanning class
  - Domain validation and cleaning
  - Subdomain enumeration
  - HTTP/HTTPS checking
  - Port scanning
  - TLS detection
  - IP resolution
- **Agent**: User-Agent management

### Orchestrator Module (`lib/orchestrator.py`)
- **ScannerOrchestrator**: Pipeline management
  - Dependency checking
  - External tool execution (subfinder, bugscanner-go)
  - File-based scanning
  - Result aggregation

## Improvements in v1.1 ✅

- ✅ Fixed missing `ssl` import
- ✅ Improved error handling with proper exception types
- ✅ Added comprehensive logging system
- ✅ Modularized code (lib/ packages)
- ✅ Removed code duplication
- ✅ Better type hints
- ✅ Enhanced documentation
- ✅ CLI mode with argparse

## Roadmap 🗺️

- [ ] JSON/CSV export formats
- [ ] Configuration file support (.yaml)
- [ ] Screenshot capturing
- [ ] Technology detection (Wappalyzer)
- [ ] Vulnerability database integration
- [ ] Web UI dashboard
- [ ] Docker containerization
- [ ] Unit & integration tests

## Troubleshooting

### subfinder not found
```bash
# Install manually
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.5.9/subfinder_2.5.9_linux_amd64.zip
unzip subfinder_2.5.9_linux_amd64.zip
sudo mv subfinder /usr/local/bin/
```

### Connection timeout errors
Increase timeout:
```bash
python3 main.py -d example.com --timeout 10
```

### Too many redirects
Use custom redirect limit (in code):
```python
checker = HostResponse(..., max_redirects=10)
```

## License

This project is licensed under the MIT License.

## Author

- **Original**: Wannazid
- **Modified & Enhanced**: kuhujiban1c

## Contributing

Feel free to submit issues and pull requests!

## Support

For issues and questions: [GitHub Issues](https://github.com/kuhujiban1c/scanner/issues)
