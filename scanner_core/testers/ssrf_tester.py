from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class SsrfTester(BaseTester):
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
            for payload_config in self.payloads:
                payload = payload_config.get('payload')
                indicator = payload_config.get('indicator')
                subcategory = payload_config.get('subcategory')
                if not all([payload, indicator, subcategory]):
                    continue

                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    if resp and indicator.lower() in resp.text.lower():
                        return Vulnerability(
                            type='Server-Side Request Forgery (SSRF)',
                            subcategory=subcategory,
                            url=test_url,
                            details={
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'The response contained the indicator string "{indicator}".'
                            },
                            severity='Critical'
                        )
                except requests.RequestException:
                    continue
                finally:
                    query_params[param] = original_value

        return None