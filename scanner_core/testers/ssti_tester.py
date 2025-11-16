from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class SstiTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads_config = self.config.get('payloads', [])

    def test(self, url: str) -> Optional[Vulnerability]:
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return None

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            original_value = query_params[param]
            for config in self.payloads_config:
                payload = config.get('payload')
                expected_response = config.get('response')
                engine = config.get('engine')
                subcategory = config.get('subcategory', 'Generic SSTI')

                if not all([payload, expected_response, engine]):
                    continue

                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    if resp and expected_response in resp.text:
                        return Vulnerability(
                            type='Server-Side Template Injection (SSTI)',
                            subcategory=subcategory,
                            url=test_url,
                            details={
                                'parameter': param,
                                'payload': payload,
                                'engine_detected': engine,
                                'evidence': f'The response contained the expected output "{expected_response}".'
                            },
                            severity='Critical'
                        )
                except requests.RequestException:
                    continue
                finally:
                    query_params[param] = original_value

        return None