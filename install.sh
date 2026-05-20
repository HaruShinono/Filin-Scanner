#!/bin/bash

# ==============================================================================
# Filin Web Vulnerability Scanner - Automated Installation Script
# Operating System: Linux (Debian/Ubuntu/Kali Linux recommended)
# ==============================================================================

# --- Define Colors for Output ---
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
echo "  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\`m-m\`        |   |    |   | |       ||   | | | |   |      "
echo "      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀         |___|    |___| |_______||___| |_|  |__|      "
echo -e "${NC}"
echo -e "${YELLOW}[*] Starting Automated Installation for Filin Scanner...${NC}\n"

# --- 1. Privilege Check ---
# Đảm bảo KHÔNG chạy thẳng bằng root để tránh lỗi phân quyền cho thư mục venv sau này
if [ "$EUID" -eq 0 ]; then
  echo -e "${RED}[!] Please DO NOT run this script as root (Don't use 'sudo ./install.sh').${NC}"
  echo -e "${YELLOW}[!] Run it as your normal user. The script will prompt for your sudo password when necessary.${NC}"
  exit 1
fi

echo -e "${YELLOW}[1/5] Updating system and installing core dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip

echo -e "${YELLOW}[2/5] Installing external security tools and libraries...${NC}"
# Cài đặt các công cụ quét và thư viện hỗ trợ render PDF (WeasyPrint)
sudo apt install -y nmap sqlmap dnsrecon nuclei python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0

echo -e "${YELLOW}[3/5] Setting up Local AI (Ollama & DeepSeek Coder)...${NC}"
# Kiểm tra xem ollama đã được cài chưa
if ! command -v ollama &> /dev/null; then
    echo -e "${GREEN}[+] Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo -e "${GREEN}[+] Ollama is already installed. Skipping.${NC}"
fi

# Khởi động service ollama nếu nó đang tắt (dùng cho Linux)
sudo systemctl enable --now ollama 2>/dev/null || true
sleep 3 # Đợi vài giây để service khởi động hẳn

echo -e "${GREEN}[+] Pulling deepseek-coder:6.7b model (This may take a while depending on your internet speed)...${NC}"
ollama pull deepseek-coder:6.7b

echo -e "${YELLOW}[4/5] Setting up Python Virtual Environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment 'venv' created.${NC}"
else
    echo -e "${GREEN}[+] Virtual environment already exists. Skipping creation.${NC}"
fi

echo -e "${YELLOW}[5/5] Installing Python packages from requirements.txt...${NC}"
# Kích hoạt venv và cài đặt gói
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo -e "\n${GREEN}========================================================================${NC}"
echo -e "${GREEN}[V] INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}========================================================================${NC}\n"

echo -e "To start the scanner, run the following commands:"
echo -e "  ${YELLOW}source venv/bin/activate${NC}"
echo -e "  ${YELLOW}python -m flask run${NC}\n"
echo -e "Then open your browser and navigate to: ${GREEN}http://127.0.0.1:5000${NC}\n"