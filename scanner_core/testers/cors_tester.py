from typing import List
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class CorsTester(BaseTester):
    def test(self, url: str) -> List[Vulnerability]:
        return self._check_cors(url)

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        """[MỚI] Kiểm tra CORS trên các API Endpoints"""
        url = form_data['url']
        return self._check_cors(url)

    def _check_cors(self, url: str) -> List[Vulnerability]:
        vulns = []
        origin = 'https://evil-scanner.com'
        headers = {'Origin': origin, 'ngrok-skip-browser-warning': 'true'}

        try:
            response = self.session.get(
                url, headers=headers, timeout=10, allow_redirects=False, verify=False
            )

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if not acao:
                return vulns

            if acao.strip() == '*' and acac.lower() == 'true':
                vulns.append(Vulnerability(
                    type='Security Misconfiguration', subcategory='CORS: Wildcard Origin with Credentials', url=url,
                    details={'issue': 'Access-Control-Allow-Origin is set to "*" while Access-Control-Allow-Credentials is "true".'},
                    severity='High'
                ))
            elif origin in acao:
                vulns.append(Vulnerability(
                    type='Security Misconfiguration', subcategory='CORS: Reflected Origin', url=url,
                    details={'issue': 'The server reflects the arbitrary Origin header value in the ACAO header.'},
                    severity='High'
                ))
            elif 'null' in acao:
                 vulns.append(Vulnerability(
                    type='Security Misconfiguration', subcategory='CORS: Null Origin Allowed', url=url,
                    details={'issue': 'The server allows the "null" origin, which can be exploited by sandboxed documents.'},
                    severity='Medium'
                ))
        except requests.RequestException:
            pass

        return vulns