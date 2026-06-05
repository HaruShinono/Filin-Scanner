#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo " ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀,     ,        _______  ___   ___      ___   __    _       "
echo " ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀)\___/(       |       ||   | |   |    |   | |  |  | |      "
echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{(@)v(@)}      |    ___||   | |   |    |   | |   |_| |      "
echo " ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{|~~~|}       |   |___ |   | |   |    |   | |       |      "
echo " ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{/^^^\}       |    ___||   | |   |___ |   | |  _    |      "
echo "  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀\`m-m\`        |   |    |   | |       ||   | | | |   |      "
echo "      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         |___|    |___| |_______||___| |_|  |__|      "
echo -e "${NC}"

echo -e "${YELLOW}[*] Starting Automated Installation for Filin Scanner...${NC}\n"

if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}[!] Please DO NOT run this script as root.${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/4] Updating system and installing core dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip

echo -e "${YELLOW}[2/4] Installing external security tools and libraries...${NC}"
sudo apt install -y \
    nmap dnsrecon \
    python3-cffi python3-brotli \
    libpango-1.0-0 libpangoft2-1.0-0

echo -e "${YELLOW}[3/4] Setting up Python Virtual Environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

echo -e "${YELLOW}[4/4] Installing Python packages...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install python-Wappalyzer
playwright install chromium

mkdir -p integrations

echo -e "\n${GREEN}[✓] INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${YELLOW}[*] Run: source venv/bin/activate && python3 app.py${NC}\n"