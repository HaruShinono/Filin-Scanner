from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests
from bs4 import BeautifulSoup
import re

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class XssTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])

    def test(self, url: str) -> Optional[Vulnerability]:
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return None

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            original_value = query_params[param]

            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    if not resp:
                        continue

                    content_type = resp.headers.get('Content-Type', '').lower()

                    # Nếu payload không có trong response thì bỏ qua ngay cho nhanh
                    if payload not in resp.text:
                        continue

                    # --- [TRƯỜNG HỢP 1] RESPONSE LÀ JSON (CỰC KỲ PHỔ BIẾN Ở JUICE SHOP & SPA) ---
                    if 'application/json' in content_type:
                        # Kiểm tra xem payload có bị JSON escape không
                        # Nếu API trả về nguyên xi ký tự < và > thay vì \u003c và \u003e
                        if payload in resp.text:
                            return Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='API Reflected XSS (Potential DOM)',
                                url=test_url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Unescaped payload reflected directly in JSON API response. Highly vulnerable if rendered via innerHTML in frontend.'
                                },
                                severity='High'
                            )

                    # --- [TRƯỜNG HỢP 2] RESPONSE LÀ HTML (TRUYỀN THỐNG) ---
                    elif 'text/html' in content_type:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        if self._verify_execution_context(soup, payload):
                            return Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='Reflected XSS',
                                url=test_url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Payload was reflected in an executable HTML context (script, event handler, or raw HTML).'
                                },
                                severity='High'
                            )

                except requests.RequestException:
                    continue
                finally:
                    query_params[param] = original_value

        return None

    def _verify_execution_context(self, soup: BeautifulSoup, payload: str) -> bool:
        """Xác minh payload có khả năng thực thi trong HTML không"""
        payload_str = str(payload)

        # 1. Nếu nằm trong các thẻ an toàn này -> False Positive
        safe_tags = ['textarea', 'title', 'pre', 'code', 'xmp', 'noembed', 'noframes', 'style']
        for tag in safe_tags:
            for element in soup.find_all(tag):
                if element.string and payload_str in element.string:
                    return False

                    # 2. Context trong thẻ Script
        for script in soup.find_all('script'):
            if script.string and payload_str in script.string:
                # Nếu nằm trong ngoặc kép thì có thể chưa thoát ra được (Cần Polyglot)
                if f'"{payload_str}"' in script.string or f"'{payload_str}'" in script.string:
                    # Nếu payload không chứa dấu đóng ngoặc (') hoặc (") để break context
                    if not any(c in payload_str for c in ["'", '"']):
                        return False
                return True

                # 3. Context trong Event Handler (onmouseover, onerror...)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower().startswith('on'):
                    if isinstance(value, str) and payload_str in value:
                        return True
                    elif isinstance(value, list) and any(payload_str in v for v in value):
                        return True

        # 4. Context Raw HTML (Tạo ra thẻ mới)
        if payload_str.startswith('<') and payload_str in str(soup):
            return True

        return False