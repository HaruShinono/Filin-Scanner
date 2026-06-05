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

# Kiểm tra không chạy với quyền root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}[!] Please DO NOT run this script as root (Don't use 'sudo ./install.sh').${NC}"
    exit 1
fi

# ─────────────────────────────────────────────
echo -e "${YELLOW}[1/7] Updating system and installing core dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip nodejs npm

# ─────────────────────────────────────────────
echo -e "${YELLOW}[2/7] Installing external security tools and libraries...${NC}"
sudo apt install -y \
    nmap sqlmap dnsrecon nuclei \
    python3-cffi python3-brotli \
    libpango-1.0-0 libpangoft2-1.0-0 \
    whatweb

# ─────────────────────────────────────────────
echo -e "${YELLOW}[3/7] Installing Retire.js CLI...${NC}"
sudo npm install -g retire

# ─────────────────────────────────────────────
echo -e "${YELLOW}[4/7] Setting up Local AI (Ollama & DeepSeek Coder)...${NC}"
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
sudo systemctl enable --now ollama 2>/dev/null || true
sleep 3
ollama pull deepseek-coder:6.7b

# ─────────────────────────────────────────────
echo -e "${YELLOW}[5/7] Setting up Python Virtual Environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# ─────────────────────────────────────────────
echo -e "${YELLOW}[6/7] Installing Python packages...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install python-wappalyzer
playwright install chromium

# ─────────────────────────────────────────────
echo -e "${YELLOW}[7/7] Cloning integration tools...${NC}"
mkdir -p integrations

# waf-bypass-tool
if [ ! -d "integrations/waf-bypass-tool" ]; then
    git clone https://github.com/geeknik/waf-bypass-tool integrations/waf-bypass-tool
    echo -e "${GREEN}[✓] waf-bypass-tool cloned.${NC}"
else
    echo -e "${YELLOW}[~] waf-bypass-tool already exists. Skipping.${NC}"
fi

if [ -f "integrations/waf-bypass-tool/requirements.txt" ]; then
    echo -e "${YELLOW}[*] Installing waf-bypass-tool dependencies...${NC}"
    pip install -r integrations/waf-bypass-tool/requirements.txt
    echo -e "${GREEN}[✓] waf-bypass-tool dependencies installed.${NC}"
fi

# ─────────────────────────────────────────────
echo -e "\n${GREEN}[✓] INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${YELLOW}[*] Run: source venv/bin/activate && python3 filin.py${NC}\n"