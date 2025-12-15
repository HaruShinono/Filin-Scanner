import re
from typing import List
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester
from integrations.retirejs_provider import get_retirejs_database, check_library_version


class OutdatedComponentTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        # Tải database ngay khi khởi tạo scanner
        self.retire_db = get_retirejs_database()

        # Mặc định một số regex để nhận diện tên thư viện từ URL/Script
        # Retire.js DB cũng có regex nhưng để đơn giản ta dùng map này kết hợp
        self.lib_patterns = {
            'jquery': r'jquery[.-]v?([0-9.]+)',
            'bootstrap': r'bootstrap[.-]v?([0-9.]+)',
            'angular': r'angular[.-]v?([0-9.]+)',
            'react': r'react[.-]v?([0-9.]+)',
            'vue': r'vue[.-]v?([0-9.]+)',
            'moment': r'moment[.-]v?([0-9.]+)',
            'lodash': r'lodash[.-]v?([0-9.]+)'
        }

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp or 'text/html' not in resp.headers.get('Content-Type', '').lower():
                return vulns

            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', src=True)

            for script in scripts:
                src = script.get('src')
                if not src: continue

                # 1. Nhận diện thư viện và version từ URL (filename)
                # Ví dụ: /js/jquery-3.5.1.min.js
                lib_name = None
                detected_version = None

                src_lower = src.lower()

                for name, pattern in self.lib_patterns.items():
                    if name in src_lower:
                        match = re.search(pattern, src_lower)
                        if match:
                            lib_name = name
                            detected_version = match.group(1)
                            break

                # Nếu không tìm thấy trong URL, có thể fetch file JS để check header (Optional - Tốn thời gian)
                # Ở đây ta tập trung vào filename cho nhanh

                if lib_name and detected_version:
                    # 2. Tra cứu trong database Retire.js
                    known_vulns = check_library_version(lib_name, detected_version, self.retire_db)

                    if known_vulns:
                        # Chọn severity cao nhất tìm được
                        highest_severity = 'Medium'
                        details_list = []

                        for v in known_vulns:
                            sev = v['severity'].title()  # low -> Low
                            if sev == 'High' or sev == 'Critical':
                                highest_severity = sev

                            details_list.append({
                                'severity': sev,
                                'identifiers': v['identifiers'],
                                'info': v['info']
                            })

                        vulns.append(Vulnerability(
                            type='Using Components with Known Vulnerabilities',
                            subcategory=f'{lib_name.title()} {detected_version}',
                            url=url,
                            details={
                                'library': lib_name,
                                'version': detected_version,
                                'resource': src,
                                'vulnerabilities': details_list
                            },
                            severity=highest_severity
                        ))

        except Exception as e:
            pass

        return vulns