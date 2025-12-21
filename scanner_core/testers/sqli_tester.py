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

        # Fetch baseline response for comparison
        base_response = self.fetch(url)
        if not base_response:
            return None

        for param in query_params:
            original_value = query_params[param]

            # --- 1. ERROR-BASED VERIFICATION ---
            for payload in self.error_payloads:
                try:
                    resp = self._inject_payload(parsed_url, query_params, param, payload)
                    if resp and any(err.lower() in resp.text.lower() for err in self.error_patterns):
                        # VERIFY: Inject a safe payload (e.g., an integer) to see if the error disappears.
                        # If the error persists with safe input, it's likely a hardcoded error message (False Positive).
                        safe_val = "123456"
                        safe_resp = self._inject_payload(parsed_url, query_params, param, safe_val)

                        has_error_safe = any(err.lower() in safe_resp.text.lower() for err in
                                             self.error_patterns) if safe_resp else False

                        if not has_error_safe:
                            return Vulnerability(
                                type='SQL Injection',
                                subcategory='Error-Based',
                                url=url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'SQL error message appeared with payload but disappeared with safe input.'
                                },
                                severity='High'
                            )
                except requests.RequestException:
                    continue

            # --- 2. TIME-BASED VERIFICATION ---
            for payload in self.time_payloads:
                try:
                    start_time = time.time()
                    self._inject_payload(parsed_url, query_params, param, payload)
                    elapsed_time = time.time() - start_time

                    if elapsed_time > self.time_delay_threshold:
                        # VERIFY: Send the request again with a benign value (original value)
                        # to ensure the server isn't just naturally slow.
                        start_verify = time.time()
                        self._inject_payload(parsed_url, query_params, param, str(original_value[0]))
                        elapsed_verify = time.time() - start_verify

                        if elapsed_verify < 2:  # If normal request is fast (<2s) but payload is slow (>Threshold)
                            return Vulnerability(
                                type='SQL Injection',
                                subcategory='Time-Based',
                                url=url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'response_time_payload': f'{elapsed_time:.2f}s',
                                    'response_time_normal': f'{elapsed_verify:.2f}s',
                                    'evidence': 'Server response was significantly delayed by the payload.'
                                },
                                severity='High'
                            )
                except requests.RequestException:
                    continue

            # --- 3. BOOLEAN-BASED VERIFICATION ---
            # Logic: Page(AND 1=1) should be similar to Baseline.
            #        Page(AND 1=2) should be different from Baseline.
            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"

            try:
                resp_true = self._inject_payload(parsed_url, query_params, param, true_payload)
                resp_false = self._inject_payload(parsed_url, query_params, param, false_payload)

                if resp_true and resp_false:
                    sim_true = self._calculate_similarity(base_response.text, resp_true.text)
                    sim_false = self._calculate_similarity(base_response.text, resp_false.text)

                    # Thresholds: True payload matches baseline > 95%, False payload matches < 90%
                    if sim_true > 0.95 and sim_false < 0.90:
                        return Vulnerability(
                            type='SQL Injection',
                            subcategory='Boolean-Based',
                            url=url,
                            details={
                                'parameter': param,
                                'true_payload': true_payload,
                                'false_payload': false_payload,
                                'similarity_true': f"{sim_true:.2f}",
                                'similarity_false': f"{sim_false:.2f}",
                                'evidence': 'Response content differs significantly between TRUE and FALSE conditions.'
                            },
                            severity='High'
                        )
            except requests.RequestException:
                continue

        return None

    def _inject_payload(self, parsed_url, params, target_param, payload):
        test_params = params.copy()
        test_params[target_param] = payload
        test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
        # Force a fresh request without using the cache for injection attempts
        return self.session.get(test_url, timeout=15, verify=False)