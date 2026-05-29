#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

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
  echo -e "${RED}[!] Please DO NOT run this script as root (Don't use 'sudo ./install.sh').${NC}"
  exit 1
fi

echo -e "${YELLOW}[1/6] Updating system and installing core dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip nodejs npm

echo -e "${YELLOW}[2/6] Installing external security tools and libraries...${NC}"
sudo apt install -y nmap sqlmap dnsrecon nuclei python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0

echo -e "${YELLOW}[3/6] Installing Retire.js CLI...${NC}"
# Cài đặt Retire.js thông qua npm
sudo npm install -g retire

echo -e "${YELLOW}[4/6] Setting up Local AI (Ollama & DeepSeek Coder)...${NC}"
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
sudo systemctl enable --now ollama 2>/dev/null || true
sleep 3
# ollama pull deepseek-coder:6.7b # Đã tải rồi thì có thể comment lại cho nhanh

echo -e "${YELLOW}[5/6] Setting up Python Virtual Environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

echo -e "${YELLOW}[6/6] Installing Python packages...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium

echo -e "\n${GREEN}[V] INSTALLATION COMPLETED SUCCESSFULLY!${NC}"