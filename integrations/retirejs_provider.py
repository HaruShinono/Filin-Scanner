# integrations/retirejs_provider.py
import requests
import json
import os
import time
from packaging import version

# URL chính thức của Retire.js repository
RETIRE_JS_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository.json"
CACHE_FILE = "retirejs_repository.json"
CACHE_DURATION = 86400  # 24 giờ

def get_retirejs_database():
    """Tải và cache database Retire.js"""
    if os.path.exists(CACHE_FILE):
        file_age = time.time() - os.path.getmtime(CACHE_FILE)
        if file_age < CACHE_DURATION:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)

    try:
        print("Downloading Retire.js database...")
        resp = requests.get(RETIRE_JS_REPO_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            return data
    except Exception as e:
        print(f"Failed to download Retire.js DB: {e}")
        # Nếu lỗi và có file cũ thì dùng tạm
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    return {}

def check_library_version(lib_name, detected_version, db):
    """
    Kiểm tra version có bị lỗi thời dựa trên DB của Retire.js
    Trả về danh sách CVE nếu có.
    """
    if lib_name not in db:
        return []

    lib_info = db[lib_name]
    vulnerabilities = []

    try:
        det_ver = version.parse(detected_version)
    except:
        return []

    # Database Retire.js có cấu trúc: "vulnerabilities": [{"below": "1.2.3", "identifiers": {...}}]
    for vuln in lib_info.get('vulnerabilities', []):
        below_ver_str = vuln.get('below')
        at_or_above_str = vuln.get('atOrAbove')

        is_vuln = False
        try:
            if below_ver_str:
                if det_ver < version.parse(below_ver_str):
                    is_vuln = True
                    # Nếu có ràng buộc dưới (atOrAbove)
                    if at_or_above_str and det_ver < version.parse(at_or_above_str):
                        is_vuln = False
        except:
            continue

        if is_vuln:
            vulnerabilities.append({
                'severity': vuln.get('severity', 'medium'),
                'identifiers': vuln.get('identifiers', {}),
                'info': vuln.get('info', [])
            })

    return vulnerabilities