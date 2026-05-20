import requests
import json
import os
import time
from packaging import version
import logging

logger = logging.getLogger(__name__)

RETIRE_JS_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
CACHE_FILE = "retirejs_repository.json"
CACHE_DURATION = 86400  # 24 hours


def get_retirejs_database():
    """
    Downloads and caches the Retire.js vulnerability database.
    """
    if os.path.exists(CACHE_FILE):
        file_age = time.time() - os.path.getmtime(CACHE_FILE)
        if file_age < CACHE_DURATION:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)

    try:
        print("  [Retire.js] Downloading updated vulnerability database...", flush=True)
        resp = requests.get(RETIRE_JS_REPO_URL, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            print("  [Retire.js] Database download complete.", flush=True)
            return data
    except Exception as e:
        logger.error(f"Failed to download Retire.js DB: {e}")
        # Fallback to old cache if download fails
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    return {}


def check_library_vulnerabilities(detected_version_str: str, lib_data: dict) -> list:
    """
    Compares a detected version against the vulnerabilities in the library's database entry.
    """
    vulnerabilities_found = []

    try:
        detected_ver = version.parse(detected_version_str)
    except version.InvalidVersion:
        return []

    for vuln in lib_data.get('vulnerabilities', []):
        is_vulnerable = False
        try:
            # Check if version is below the vulnerable threshold
            if 'below' in vuln and detected_ver < version.parse(vuln['below']):
                # If there's a lower bound, ensure the version is within that range
                if 'atOrAbove' in vuln and detected_ver < version.parse(vuln['atOrAbove']):
                    is_vulnerable = False
                else:
                    is_vulnerable = True
        except version.InvalidVersion:
            continue

        if is_vulnerable:
            vulnerabilities_found.append({
                'severity': vuln.get('severity', 'medium'),
                'identifiers': vuln.get('identifiers', {}),
                'info': vuln.get('info', [])
            })

    return vulnerabilities_found