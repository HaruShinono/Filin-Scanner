import base64
import json
import re
from http.cookies import SimpleCookie
from typing import List
from urllib.parse import urlparse

import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class CryptoTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.security_headers_to_check = self.config.get('security_headers', [])
        self.sensitive_cookie_keywords = self.config.get('sensitive_cookie_keywords', [])
        self.jwt_regex_pattern = self.config.get('jwt_regex', '')

    def test(self, url: str) -> List[Vulnerability]:
        return self._run_crypto_test(url, 'GET')

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        """[MỚI] Kiểm tra Header và Cookie bảo mật trên API"""
        url = form_data['url']
        method = form_data.get('method', 'POST').upper()
        return self._run_crypto_test(url, method)

    def _run_crypto_test(self, url: str, method: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)

        if parsed_url.scheme != 'https':
            vulns.append(Vulnerability(
                type='Cryptographic Failure', subcategory='Unencrypted Connection', url=url,
                details={'issue': 'The connection to this URL is not encrypted (HTTP).'}, severity='High',
            ))

        try:
            if method == 'GET':
                resp = self.fetch(url, headers={'ngrok-skip-browser-warning': 'true'})
            else:
                resp = self.session.post(url, data={}, timeout=10, verify=False,
                                         headers={'ngrok-skip-browser-warning': 'true'})

            if not resp: return vulns

            content_type = resp.headers.get('Content-Type', '').lower()
            if any(ct in content_type for ct in ['image/', 'font/', 'video/', 'audio/']): return vulns

            if 'text/html' in content_type or 'application/json' in content_type:
                for header in self.security_headers_to_check:
                    if header.lower() not in (h.lower() for h in resp.headers):
                        vulns.append(Vulnerability(
                            type='Security Misconfiguration', subcategory='Missing Security Header', url=url,
                            details={'issue': f'The security header "{header}" is missing.'}, severity='Medium'
                        ))

            raw_cookies = resp.headers.get('Set-Cookie', '')
            if raw_cookies:
                cookie_jar = SimpleCookie()
                cookie_jar.load(raw_cookies)
                for cookie_name, cookie in cookie_jar.items():
                    if any(keyword in cookie_name.lower() for keyword in self.sensitive_cookie_keywords):
                        if not cookie.get('secure'):
                            vulns.append(Vulnerability(
                                type='Cryptographic Failure', subcategory='Insecure Cookie', url=url,
                                details={'issue': f'Sensitive cookie "{cookie_name}" is missing the "Secure" flag.'},
                                severity='Medium'
                            ))
                        if not cookie.get('httponly'):
                            vulns.append(Vulnerability(
                                type='Cryptographic Failure', subcategory='Insecure Cookie', url=url,
                                details={'issue': f'Sensitive cookie "{cookie_name}" is missing the "HttpOnly" flag.'},
                                severity='Low'
                            ))

            jwt_token = None
            auth_header = resp.headers.get('Authorization', '')
            if auth_header.lower().startswith('bearer '):
                jwt_token = auth_header[7:]
            elif self.jwt_regex_pattern:
                match = re.search(self.jwt_regex_pattern, resp.text)
                if match: jwt_token = match.group(0)

            if jwt_token:
                try:
                    parts = jwt_token.split('.')
                    if len(parts) == 3:
                        header_part = parts[0]
                        padding = '=' * (4 - len(header_part) % 4)
                        decoded_header = base64.urlsafe_b64decode(header_part + padding).decode('utf-8')
                        header_json = json.loads(decoded_header)
                        if header_json.get('alg', '').lower() == 'none':
                            vulns.append(Vulnerability(
                                type='Cryptographic Failure', subcategory='Weak JWT Algorithm', url=url,
                                details={'issue': f'A JWT with the insecure algorithm "alg=none" was found.'},
                                severity='High'
                            ))
                except Exception:
                    pass

        except requests.RequestException:
            pass
        return vulns