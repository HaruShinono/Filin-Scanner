from typing import List
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class CorsTester(BaseTester):
    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        origin = 'https://evil-scanner.com'
        headers = {'Origin': origin}

        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if not acao:
                return vulns

            # Test 1: Wildcard origin with credentials allowed
            if acao.strip() == '*' and acac.lower() == 'true':
                vulns.append(Vulnerability(
                    type='CORS Misconfiguration',
                    subcategory='Wildcard Origin with Credentials',
                    url=url,
                    details={
                        'issue': 'Access-Control-Allow-Origin is set to "*" while Access-Control-Allow-Credentials is "true".',
                        'Access-Control-Allow-Origin': acao,
                        'Access-Control-Allow-Credentials': acac
                    },
                    severity='High'
                ))

            # Test 2: Arbitrary origin reflected
            elif origin in acao:
                vulns.append(Vulnerability(
                    type='CORS Misconfiguration',
                    subcategory='Reflected Origin',
                    url=url,
                    details={
                        'issue': 'The server reflects the arbitrary Origin header value in the ACAO header.',
                        'Access-Control-Allow-Origin': acao,
                        'Access-Control-Allow-Credentials': acac
                    },
                    severity='High'
                ))

            # Test 3: Null origin allowed (less common but still a risk)
            elif 'null' in acao:
                vulns.append(Vulnerability(
                    type='CORS Misconfiguration',
                    subcategory='Null Origin Allowed',
                    url=url,
                    details={
                        'issue': 'The server allows the "null" origin, which can be exploited by sandboxed documents.',
                        'Access-Control-Allow-Origin': acao,
                    },
                    severity='Medium'
                ))

        except requests.RequestException:
            pass

        return vulns