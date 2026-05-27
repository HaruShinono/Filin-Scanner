import random
import traceback
from typing import Optional, List
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
        if 'php://filter' in payload:
            return 'PHP Wrapper LFI'
        return 'Generic File Inclusion'

    def _generate_verify_payload(self, payload: str) -> str:
        """Hàm dùng chung để tạo payload đối chứng (file không tồn tại)"""
        fake_file = f"non_existent_file_{random.randint(1000, 9999)}"
        if "win.ini" in payload:
            return payload.replace("win.ini", fake_file)
        elif "passwd" in payload:
            return payload.replace("passwd", fake_file)
        elif "shadow" in payload:
            return payload.replace("shadow", fake_file)
        elif "boot.ini" in payload:
            return payload.replace("boot.ini", fake_file)
        elif "environ" in payload:
            return payload.replace("environ", fake_file)
        else:
            return payload + fake_file

    def test(self, url: str) -> List[Vulnerability]:
        """Test LFI trên các URL truyền thống (GET Query Parameters)"""
        vulns = []
        parsed_url = urlparse(url)
        if not parsed_url.query or not self.payloads:
            return vulns

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    # Nếu tìm thấy indicator (ví dụ: root:x:0:0)
                    if resp and any(indicator.lower() in resp.text.lower() for indicator in self.indicators):

                        # --- VERIFY LOGIC ---
                        verify_payload = self._generate_verify_payload(payload)
                        verify_params = query_params.copy()
                        verify_params[param] = verify_payload
                        verify_url = urlunparse(parsed_url._replace(query=urlencode(verify_params, doseq=True)))

                        # Bắn payload giả để đối chứng (Bypass cache)
                        verify_resp = self.session.get(verify_url, timeout=10, verify=False,
                                                       headers={'ngrok-skip-browser-warning': 'true'})

                        has_indicator_verify = False
                        if verify_resp:
                            has_indicator_verify = any(
                                ind.lower() in verify_resp.text.lower() for ind in self.indicators)

                        # Nếu file giả KHÔNG hiện ra indicator -> Lỗ hổng là thật!
                        if not has_indicator_verify:
                            subcategory = self._determine_subcategory(payload)
                            vulns.append(Vulnerability(
                                type='Local File Inclusion',
                                subcategory=subcategory,
                                url=test_url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'control_payload': verify_payload,
                                    'evidence': 'Sensitive content found with payload but disappeared with control payload.'
                                },
                                severity='High'
                            ))
                            break  # Chuyển sang param tiếp theo để tránh spam

                except requests.RequestException:
                    continue

        return vulns

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        """Kiểm tra LFI trên Form POST/PUT và JSON API"""
        vulns = []
        try:
            url = form_data['url']
            method = form_data.get('method', 'POST').upper()
            inputs = form_data.get('inputs', [])
            is_api = form_data.get('is_api', False) or any(
                k in url.lower() for k in ['/api/', '/rest/', '/v1/', '/ftp'])
            captured_headers = form_data.get('headers', {})

            print(f"  [DEBUG-LFI] Analyzing Endpoint: {method} {url} (Is API: {is_api})", flush=True)

            for target_input in inputs:
                if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']:
                    continue

                param = target_input['name']

                for payload in self.payloads:
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api, captured_headers)
                        if not resp:
                            continue

                        if any(indicator.lower() in resp.text.lower() for indicator in self.indicators):
                            print(f"  [DEBUG-LFI] Payload triggered indicator on [{param}]! Verifying...", flush=True)

                            # --- VERIFY LOGIC TRÊN API ---
                            verify_payload = self._generate_verify_payload(payload)
                            verify_resp = self._inject_form_payload(url, method, inputs, param, verify_payload, is_api,
                                                                    captured_headers)

                            has_indicator_verify = False
                            if verify_resp:
                                has_indicator_verify = any(
                                    ind.lower() in verify_resp.text.lower() for ind in self.indicators)

                            # Nếu file ảo KHÔNG lộ indicator -> Xác nhận lỗ hổng
                            if not has_indicator_verify:
                                print(f"  [DEBUG-LFI] !!! LFI SUCCESS ON API !!!", flush=True)
                                subcategory = self._determine_subcategory(payload)
                                vulns.append(Vulnerability(
                                    type='Local File Inclusion', subcategory=subcategory, url=url,
                                    details={
                                        'parameter': f"Body/Query: {param}", 'payload': payload,
                                        'control_payload': verify_payload,
                                        'evidence': 'Sensitive file contents exfiltrated via API endpoint successfully.'
                                    },
                                    severity='High'
                                ))
                                break  # Chuyển param
                    except requests.RequestException as e:
                        print(f"  [DEBUG-LFI] Request error: {e}", flush=True)
        except Exception as e:
            print(f"  [DEBUG-LFI-CRASH] Exception in test_form: {e}", flush=True)
            traceback.print_exc()

        return vulns

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False, extra_headers=None):
        """Hàm đóng gói dữ liệu và gửi HTTP Request"""
        data = {}
        for inp in inputs:
            data[inp['name']] = payload if inp['name'] == target_param else inp.get('value', 'test')

        headers = {'ngrok-skip-browser-warning': 'true', 'Accept': 'application/json, text/plain, */*'}

        # Bơm Token Authentication vào Header
        if extra_headers:
            headers.update(extra_headers)

        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)

            if is_api:
                headers['Content-Type'] = 'application/json'
                if method == 'PUT': return self.session.put(url, json=data, timeout=10, verify=False, headers=headers)
                elif method == 'PATCH': return self.session.patch(url, json=data, timeout=10, verify=False, headers=headers)
                elif method == 'DELETE': return self.session.delete(url, json=data, timeout=10, verify=False, headers=headers)
                return self.session.post(url, json=data, timeout=10, verify=False, headers=headers)
            else:
                return self.session.post(url, data=data, timeout=10, verify=False, headers=headers)
        except Exception:
            return None