import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class SqliTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.error_payloads = self.config.get('error_based_payloads', [])
        self.time_payloads = self.config.get('time_based_payloads', [])
        self.boolean_payloads = self.config.get('boolean_based_payloads', [])
        self.error_patterns = self.config.get('error_patterns', [])
        self.time_delay_threshold = self.config.get('time_delay_seconds', 4)

    def test(self, url: str) -> Optional[Vulnerability]:
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return None

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            original_value = query_params[param]

            # Test 1: Error-Based SQLi
            for payload in self.error_payloads:
                try:
                    resp = self._inject_payload(parsed_url, query_params, param, payload)
                    if resp and any(err.lower() in resp.text.lower() for err in self.error_patterns):
                        return Vulnerability(
                            type='SQL Injection', subcategory='Error-Based', url=url,
                            details={'parameter': param, 'payload': payload,
                                     'evidence': 'SQL error message found in response.'},
                            severity='High'
                        )
                except requests.RequestException:
                    continue

            # Test 2: Time-Based SQLi
            for payload in self.time_payloads:
                try:
                    start_time = time.time()
                    self._inject_payload(parsed_url, query_params, param, payload)
                    elapsed_time = time.time() - start_time
                    if elapsed_time > self.time_delay_threshold:
                        return Vulnerability(
                            type='SQL Injection', subcategory='Time-Based', url=url,
                            details={'parameter': param, 'payload': payload,
                                     'evidence': f'Server response delayed by {elapsed_time:.2f} seconds.'},
                            severity='High'
                        )
                except requests.RequestException:
                    continue

            # Test 3: Boolean-Based SQLi
            for payload_pair in self.boolean_payloads:
                true_payload = payload_pair.get('true')
                false_payload = payload_pair.get('false')
                if not true_payload or not false_payload:
                    continue
                try:
                    true_resp = self._inject_payload(parsed_url, query_params, param, true_payload)
                    false_resp = self._inject_payload(parsed_url, query_params, param, false_payload)

                    if true_resp and false_resp and (len(true_resp.content) != len(false_resp.content)):
                        return Vulnerability(
                            type='SQL Injection', subcategory='Boolean-Based', url=url,
                            details={'parameter': param, 'payload': true_payload,
                                     'evidence': 'Response content differs for TRUE and FALSE conditions.'},
                            severity='High'
                        )
                except requests.RequestException:
                    continue

            query_params[param] = original_value

        return None

    def _inject_payload(self, parsed_url, params, target_param, payload):
        test_params = params.copy()
        test_params[target_param] = payload
        test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
        return self.fetch(test_url)