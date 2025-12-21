# scanner_core/testers/api_tester.py
import requests
import json
from typing import List, Optional
from urllib.parse import urljoin
from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class ApiTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.swagger_paths = self.config.get('swagger_paths', [])

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []

        # Chỉ chạy module này trên root URL hoặc nếu URL có vẻ là API doc
        # Để tránh spam request trên mọi sub-page
        if not (url.endswith('/') or 'api' in url or 'doc' in url):
            return vulns

        # 1. Discovery: Cố gắng tìm file Swagger/OpenAPI
        found_swagger_url = None
        for path in self.swagger_paths:
            target = urljoin(url, path)
            try:
                resp = self.fetch(target)
                if resp and resp.status_code == 200:
                    # Check nếu nội dung là JSON và có từ khóa swagger/openapi
                    try:
                        data = json.loads(resp.text)
                        if 'swagger' in data or 'openapi' in data:
                            found_swagger_url = target
                            vulns.append(Vulnerability(
                                type='API Exposure',
                                subcategory='Swagger/OpenAPI Documentation',
                                url=target,
                                details={'evidence': 'Publicly accessible API documentation found.'},
                                severity='Low'
                            ))
                            # Đã tìm thấy thì dừng loop discovery
                            break
                    except:
                        pass
            except:
                pass

        # 2. Parsing & Analysis: Nếu tìm thấy Swagger, phân tích các endpoint
        if found_swagger_url:
            try:
                api_vulns = self._analyze_swagger(found_swagger_url)
                vulns.extend(api_vulns)
            except Exception as e:
                pass

        return vulns

    def _analyze_swagger(self, swagger_url: str) -> List[Vulnerability]:
        vulns = []
        resp = self.fetch(swagger_url)
        data = json.loads(resp.text)

        paths = data.get('paths', {})
        base_path = data.get('basePath', '')

        # Kiểm tra các API nguy hiểm không yêu cầu xác thực (Logic đơn giản)
        # Trong thực tế cần check securityDefinitions

        risky_methods = ['delete', 'put', 'patch']
        sensitive_keywords = ['admin', 'config', 'users', 'system', 'backup']

        for endpoint, methods in paths.items():
            full_api_url = urljoin(swagger_url, base_path + endpoint)

            for method_name, details in methods.items():
                # Check 1: Unsafe HTTP Methods exposed
                if method_name.lower() in risky_methods:
                    vulns.append(Vulnerability(
                        type='API Security',
                        subcategory='Unsafe HTTP Method',
                        url=full_api_url,
                        details={
                            'method': method_name.upper(),
                            'endpoint': endpoint,
                            'note': 'Potentially dangerous method exposed.'
                        },
                        severity='Medium'
                    ))

                # Check 2: Sensitive Information in API Paths
                if any(k in endpoint.lower() for k in sensitive_keywords):
                    vulns.append(Vulnerability(
                        type='API Security',
                        subcategory='Sensitive API Endpoint',
                        url=full_api_url,
                        details={'endpoint': endpoint, 'method': method_name.upper()},
                        severity='Medium'
                    ))

        return vulns