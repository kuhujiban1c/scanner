#!/bin/bash
#
# Scanner Installation Script
# Installs external dependencies: subfinder, bugscanner-go
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}Scanner CLI Installation${NC}"
echo -e "${GREEN}======================================${NC}\n"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Python 3 found$(NC)"

# Install Python dependencies
echo -e "\n${YELLOW}[*] Installing Python dependencies...${NC}"
pip install -q -r requirements.txt
echo -e "${GREEN}[✓] Python dependencies installed${NC}"

# Install subfinder
echo -e "\n${YELLOW}[*] Checking subfinder...${NC}"
if command -v subfinder &> /dev/null; then
    echo -e "${GREEN}[✓] subfinder is already installed${NC}"
else
    echo -e "${YELLOW}[!] subfinder not found. Installing...${NC}"
    
    # Detect OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    # Map architecture
    if [ "$ARCH" = "x86_64" ]; then
        ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        ARCH="arm64"
    fi
    
    DOWNLOAD_URL="https://github.com/projectdiscovery/subfinder/releases/download/v2.5.9/subfinder_2.5.9_${OS}_${ARCH}.zip"
    
    echo -e "${YELLOW}Downloading from: $DOWNLOAD_URL${NC}"
    
    if command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O subfinder.zip
    elif command -v curl &> /dev/null; then
        curl -sL "$DOWNLOAD_URL" -o subfinder.zip
    else
        echo -e "${RED}[!] wget or curl required${NC}"
        exit 1
    fi
    
    unzip -q subfinder.zip
    sudo mv subfinder /usr/local/bin/
    rm subfinder.zip
    
    echo -e "${GREEN}[✓] subfinder installed${NC}"
fi

# Install bugscanner-go (optional)
echo -e "\n${YELLOW}[*] Checking bugscanner-go...${NC}"
if command -v bugscanner-go &> /dev/null; then
    echo -e "${GREEN}[✓] bugscanner-go is already installed${NC}"
else
    echo -e "${YELLOW}[*] bugscanner-go is optional${NC}"
    echo -e "${YELLOW}Install manually if needed: https://github.com/projectdiscovery/naabu${NC}"
fi

echo -e "\n${GREEN}======================================${NC}"
echo -e "${GREEN}[✓] Installation complete!${NC}"
echo -e "${GREEN}======================================${NC}"
echo -e "\n${YELLOW}Quick start:${NC}"
echo -e "  ${GREEN}python3 main.py${NC} (Interactive mode)"
echo -e "  ${GREEN}python3 main.py -d example.com -o output.txt${NC} (CLI mode)"
echo -e "  ${GREEN}python3 scan.py -f domains.txt -o result.txt${NC} (Standalone scan)"
