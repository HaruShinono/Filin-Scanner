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
        if not data:
            return 0
        entropy = 0
        for char_code in range(256):
            prob = float(data.count(chr(char_code))) / len(data)
            if prob > 0:
                entropy += -prob * math.log(prob, 2)
        return entropy

    def _mask_sensitive(self, value: str) -> str:
        if len(value) > 8:
            return f"{value[:4]}...{value[-4:]}"
        return "..."

    def _get_context(self, text: str, match: re.Match, window: int = 50) -> str:
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        return text[start:end].replace('\n', ' ').strip()

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp:
                return vulns

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

                if not leak_type or not regex:
                    continue

                try:
                    matches = re.finditer(regex, text, re.IGNORECASE)
                    for match in matches:
                        value = match.group(1) if match.groups() else match.group(0)

                        if value in found_matches:
                            continue
                        found_matches.add(value)

                        if min_entropy and self._shannon_entropy(value) < min_entropy:
                            continue

                        vulns.append(Vulnerability(
                            type='Sensitive Data Exposure',
                            subcategory=subcategory,
                            url=url,
                            details={
                                'leak_type': leak_type,
                                'match': self._mask_sensitive(value),
                                'context_snippet': self._get_context(text, match)
                            },
                            severity=severity
                        ))
                except re.error:
                    continue

        except requests.RequestException:
            pass

        return vulns