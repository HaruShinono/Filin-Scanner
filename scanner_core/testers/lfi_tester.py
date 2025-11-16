from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class LfiTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])
        self.indicators = self.config.get('indicators', [])

    def _determine_subcategory(self, payload: str) -> str:
        if 'etc/passwd' in payload or 'shadow' in payload:
            return 'Path Traversal'
        if 'boot.ini' in payload or 'win.ini' in payload:
            return 'Windows File Inclusion'
        if '/proc/self/environ' in payload:
            return 'ProcFS File Inclusion'
        return 'Generic File Inclusion'

    def test(self, url: str) -> Optional[Vulnerability]:
        parsed_url = urlparse(url)
        if not parsed_url.query or not self.payloads:
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
                    if resp and any(indicator.lower() in resp.text.lower() for indicator in self.indicators):
                        subcategory = self._determine_subcategory(payload)
                        return Vulnerability(
                            type='Local File Inclusion',
                            subcategory=subcategory,
                            url=test_url,
                            details={
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'A known indicator from the included file was found in the response.'
                            },
                            severity='High'
                        )
                except requests.RequestException:
                    continue
                finally:
                    query_params[param] = original_value

        return None