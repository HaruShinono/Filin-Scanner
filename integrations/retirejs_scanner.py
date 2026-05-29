import os
import json
import tempfile
import subprocess
import requests
import logging

logger = logging.getLogger(__name__)


def run_retirejs(js_urls: list, cookies: str = None) -> list:
    """
    Tải các file JS về thư mục tạm và chạy Retire.js CLI để phân tích.
    """
    findings = []
    if not js_urls:
        return findings

    # Kiểm tra xem retire.js đã được cài đặt chưa
    if not subprocess.run(['which', 'retire'], capture_output=True).stdout:
        print("[-] Error: 'retire' CLI is not installed (Run: npm install -g retire). Skipping.", flush=True)
        return findings

    headers = {'User-Agent': 'Mozilla/5.0 Scanner', 'ngrok-skip-browser-warning': 'true'}
    cookie_dict = {}
    if cookies:
        for item in cookies.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookie_dict[k] = v

    # Tạo thư mục tạm thời
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"  [Retire.js] Downloading {len(js_urls)} JavaScript files for deep analysis...", flush=True)

        file_map = {}  # Map đường dẫn file local với URL gốc

        # 1. Tải file JS
        for i, url in enumerate(js_urls):
            try:
                resp = requests.get(url, headers=headers, cookies=cookie_dict, timeout=5, verify=False)
                if resp.status_code == 200:
                    filename = f"script_{i}.js"
                    filepath = os.path.join(tmpdir, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(resp.text)
                    file_map[filepath] = url
            except Exception:
                pass

        if not file_map:
            print("  [Retire.js] No valid JS files downloaded.", flush=True)
            return findings

        # 2. Chạy Retire.js CLI
        print(f"  [Retire.js] Analyzing files with Retire.js Engine...", flush=True)
        # --jspath: Đường dẫn thư mục cần quét
        # --outputformat json: Xuất kết quả dạng JSON
        cmd = ['retire', '--jspath', tmpdir, '--outputformat', 'json']

        # Chạy lệnh. Retire.js có thể trả về exit code khác 0 nếu có lỗ hổng, nên ta dùng check=False
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        # Kết quả JSON thường nằm ở stdout. Nếu lỗi nó có thể nằm ở stderr.
        output = result.stdout if result.stdout else result.stderr

        # 3. Phân tích Output JSON
        try:
            # Tìm đoạn JSON hợp lệ trong output (đôi khi CLI in ra vài dòng text trước JSON)
            start_idx = output.find('{')
            if start_idx != -1:
                json_str = output[start_idx:]
                data = json.loads(json_str)

                results_array = data.get('data', [])

                for item in results_array:
                    filepath = item.get('file')
                    original_url = file_map.get(filepath, "Unknown URL")

                    for res in item.get('results', []):
                        component = res.get('component')
                        version = res.get('version')
                        vulns = res.get('vulnerabilities', [])

                        if vulns:
                            # Xác định mức độ nghiêm trọng cao nhất
                            severity = 'Low'
                            for v in vulns:
                                sev = v.get('severity', '').lower()
                                if sev == 'critical':
                                    severity = 'Critical'
                                elif sev == 'high' and severity != 'Critical':
                                    severity = 'High'
                                elif sev == 'medium' and severity not in ['Critical', 'High']:
                                    severity = 'Medium'

                            findings.append({
                                'component': component,
                                'version': version,
                                'url': original_url,
                                'severity': severity,
                                'vulnerabilities': vulns
                            })
        except json.JSONDecodeError:
            print(f"  [Retire.js] Error parsing output.", flush=True)

    return findings