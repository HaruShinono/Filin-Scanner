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

        # Nhận diện cờ Windows từ scanner
        self.is_windows = self.config.get('is_windows', False)

        # Danh sách các tệp tin cấu hình và source code nhạy cảm của các framework
        self.project_files = self.config.get('project_files', [
            'package.json', 'web.config', 'main.js', 'app.js', 'config.json',
            'settings.py', 'manage.py', 'pom.xml', 'build.gradle'
        ])

    def _determine_subcategory(self, payload: str) -> str:
        if 'etc/passwd' in payload or 'shadow' in payload:
            return 'Path Traversal / LFI (Linux)'
        if 'boot.ini' in payload or 'win.ini' in payload:
            return 'Windows File Inclusion'
        if '/proc/self/environ' in payload:
            return 'ProcFS File Inclusion'
        if 'php://filter' in payload:
            return 'PHP Wrapper LFI'
        if any(f in payload for f in self.project_files):
            return 'Project Configuration Leak (LFI)'
        return 'Generic File Inclusion'

    def _generate_verify_payload(self, payload: str) -> str:
        """Tạo payload đối chứng chứa file rác không tồn tại"""
        fake_file = f"non_existent_file_{random.randint(1000, 9999)}"
        # Thay thế tên file đích bằng file rác nhưng giữ nguyên đường dẫn traversal (../../)
        for target_file in ['win.ini', 'boot.ini', 'passwd', 'shadow', 'environ', 'package.json', 'web.config',
                            'main.js']:
            if target_file in payload:
                return payload.replace(target_file, fake_file)
        return payload + fake_file

    def _get_target_payloads(self, is_file_endpoint: bool) -> List[str]:
        """[MỚI] Chọn lọc danh sách payload theo ngữ cảnh"""
        target_payloads = []

        # 1. Nếu là đường dẫn nhạy cảm liên quan đến file (ftp, download, file...)
        # Tự động tạo các payload fuzzing file dự án (ví dụ: ../../package.json)
        if is_file_endpoint:
            traversals = ["../", "../../", "../../../", "../../../../", "..\\..\\", "..\\..\\..\\"]
            for f in self.project_files:
                for trav in traversals:
                    target_payloads.append(trav + f)

        # 2. Lọc danh sách payload hệ thống theo OS
        for p in self.payloads:
            if self.is_windows:
                # Nếu là Windows, ưu tiên win.ini/boot.ini
                if "win.ini" in p or "boot.ini" in p or "\\" in p:
                    target_payloads.append(p)
            else:
                # Nếu là Linux, ưu tiên etc/passwd
                if "passwd" in p or "environ" in p or "/" in p:
                    target_payloads.append(p)

        return list(set(target_payloads))

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return vulns

        path_lower = parsed_url.path.lower()
        is_file_endpoint = any(kw in path_lower for kw in ['ftp', 'download', 'file', 'view', 'read', 'doc', 'pdf'])

        # Chọn lọc payload theo ngữ cảnh
        test_payloads = self._get_target_payloads(is_file_endpoint)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in test_payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    if not resp: continue

                    # 1. Phát hiện LFI dựa trên Indicator truyền thống (ví dụ: root:x:0:0)
                    has_indicator = any(indicator.lower() in resp.text.lower() for indicator in self.indicators)

                    # 2. [MỚI] BLIND LFI: Phát hiện dựa trên kích thước & mã lỗi (Size-based / Error-based)
                    # Sử dụng khi đọc file thành công nhưng file không chứa indicator mặc định
                    is_blind_lfi = False
                    verify_payload = self._generate_verify_payload(payload)
                    verify_params = query_params.copy()
                    verify_params[param] = verify_payload
                    verify_url = urlunparse(parsed_url._replace(query=urlencode(verify_params, doseq=True)))
                    verify_resp = self.session.get(verify_url, timeout=10, verify=False)

                    if not has_indicator:
                        # Nếu gửi payload thật trả về 200 OK (và file có dung lượng lớn),
                        # nhưng gửi file rác trả về 404/403/500 -> Khả năng cao là LFI!
                        if resp.status_code == 200 and len(resp.content) > 1000:
                            if verify_resp and verify_resp.status_code in [403, 404, 500]:
                                is_blind_lfi = True

                    # Thực hiện kiểm chứng (Verify) chống False Positive cho Indicator
                    has_indicator_verify = any(
                        ind.lower() in verify_resp.text.lower() for ind in self.indicators) if verify_resp else False

                    if (has_indicator and not has_indicator_verify) or is_blind_lfi:
                        subcategory = self._determine_subcategory(payload)
                        vulns.append(Vulnerability(
                            type='Local File Inclusion',
                            subcategory=subcategory,
                            url=test_url,
                            details={
                                'parameter': param,
                                'payload': payload,
                                'control_payload': verify_payload,
                                'evidence': 'File content read successfully (verified using control payload differences).'
                            },
                            severity='High'
                        ))
                        break

                except requests.RequestException:
                    continue

        return vulns

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        """Kiểm tra LFI trên Form POST/PUT và JSON API"""
        vulns = []
        try:
            url = form_data['url']
            method = form_data.get('method', 'POST').upper()
            inputs = form_data['inputs']
            is_api = form_data.get('is_api', False) or any(
                k in url.lower() for k in ['/api/', '/rest/', '/v1/', '/ftp'])
            captured_headers = form_data.get('headers', {})

            is_file_endpoint = any(
                kw in url.lower() for kw in ['ftp', 'download', 'file', 'view', 'read', 'doc', 'pdf'])
            test_payloads = self._get_target_payloads(is_file_endpoint)

            base_resp = self._inject_form_payload(url, method, inputs, None, None, is_api, captured_headers)
            base_len = len(base_resp.content) if base_resp else 0

            for target_input in inputs:
                if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']:
                    continue

                param = target_input['name']

                for payload in test_payloads:
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api, captured_headers)
                        if not resp: continue

                        # 1. Phát hiện bằng Indicator
                        has_indicator = any(indicator.lower() in resp.text.lower() for indicator in self.indicators)

                        # 2. [MỚI] BLIND LFI TRÊN API (Chênh lệch độ dài dữ liệu lớn)
                        is_blind_lfi = False
                        verify_payload = self._generate_verify_payload(payload)
                        verify_resp = self._inject_form_payload(url, method, inputs, param, verify_payload, is_api,
                                                                captured_headers)

                        if not has_indicator and resp.status_code == 200:
                            # Nếu gửi payload thật ra nội dung lớn, gửi file rác ra lỗi 4xx/5xx hoặc rỗng
                            if verify_resp:
                                if verify_resp.status_code in [403, 404, 500]:
                                    is_blind_lfi = True
                                elif abs(len(resp.content) - len(verify_resp.content)) > 1000:
                                    is_blind_lfi = True

                        has_indicator_verify = any(ind.lower() in verify_resp.text.lower() for ind in
                                                   self.indicators) if verify_resp else False

                        if (has_indicator and not has_indicator_verify) or is_blind_lfi:
                            subcategory = self._determine_subcategory(payload)
                            vulns.append(Vulnerability(
                                type='Local File Inclusion',
                                subcategory=subcategory,
                                url=url,
                                details={
                                    'parameter': f"Body/Query: {param}",
                                    'payload': payload,
                                    'control_payload': verify_payload,
                                    'evidence': 'LFI / Path Traversal verified via size/status differences on JSON API.'
                                },
                                severity='High'
                            ))
                            break
                    except requests.RequestException:
                        pass
        except Exception:
            pass

        return vulns

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False, extra_headers=None):
        data = {}
        for inp in inputs:
            data[inp['name']] = payload if inp['name'] == target_param else inp.get('value', 'test')

        headers = {'ngrok-skip-browser-warning': 'true', 'Accept': 'application/json, text/plain, */*'}
        if extra_headers:
            headers.update(extra_headers)

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