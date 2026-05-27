import math
import re
from typing import List
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class InfoLeakTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.patterns = self.config.get('patterns', [])

    def _shannon_entropy(self, data: str) -> float:
        if not data: return 0
        entropy = 0
        for char_code in range(256):
            prob = float(data.count(chr(char_code))) / len(data)
            if prob > 0: entropy += -prob * math.log(prob, 2)
        return entropy

    def _mask_sensitive(self, value: str) -> str:
        if len(value) > 8: return f"{value[:4]}...{value[-4:]}"
        return "..."

    def test(self, url: str) -> List[Vulnerability]:
        return self._run_leak_test(url, 'GET')

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        """[MỚI] Kiểm tra Info Leak trong phản hồi của API/Form"""
        url = form_data['url']
        method = form_data.get('method', 'POST').upper()
        # Đối với Info Leak, chúng ta chỉ cần request trống (hoặc test data)
        # để xem server có lỡ "nhả" data nhạy cảm không
        return self._run_leak_test(url, method)

    def _run_leak_test(self, url: str, method: str) -> List[Vulnerability]:
        vulns = []
        try:
            if method == 'GET':
                resp = self.fetch(url, headers={'ngrok-skip-browser-warning': 'true'})
            else:
                resp = self.session.post(url, data={}, timeout=10, verify=False,
                                         headers={'ngrok-skip-browser-warning': 'true'})

            if not resp: return vulns

            content_type = resp.headers.get('Content-Type', '').lower()
            if not any(ct in content_type for ct in ['text/html', 'application/json', 'text/plain', 'javascript']):
                return vulns

            text = resp.text
            found_matches = set()

            for pattern_config in self.patterns:
                leak_type = pattern_config.get('type')
                regex = pattern_config.get('regex')
                severity = pattern_config.get('severity', 'Low')
                subcategory = pattern_config.get('subcategory', 'Generic Leak')
                min_entropy = pattern_config.get('min_entropy')

                if not leak_type or not regex: continue

                try:
                    matches = re.finditer(regex, text, re.IGNORECASE)
                    for match in matches:
                        value = match.group(1) if match.groups() else match.group(0)

                        if value in found_matches: continue
                        found_matches.add(value)

                        if min_entropy and self._shannon_entropy(value) < min_entropy: continue

                        start = max(0, match.start() - 50)
                        end = min(len(text), match.end() + 50)
                        context = text[start:end].replace('\n', ' ').strip()

                        vulns.append(Vulnerability(
                            type='Sensitive Data Exposure', subcategory=subcategory, url=url,
                            details={'leak_type': leak_type, 'match': self._mask_sensitive(value),
                                     'context_snippet': context},
                            severity=severity
                        ))
                except re.error:
                    continue
        except requests.RequestException:
            pass
        return vulns