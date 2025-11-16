from typing import List
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class AuthTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.default_creds = self.config.get('default_credentials', [])
        self.sensitive_keywords = self.config.get('sensitive_path_keywords', [])
        self.login_indicators = self.config.get('login_form_indicators', [])
        self.success_indicators = self.config.get('login_success_indicators', [])

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp:
                return vulns

            url_lc = url.lower()
            html_lc = resp.text.lower()

            # Test 1: Default credentials on login forms
            is_login_page = any(indicator in url_lc or indicator in html_lc for indicator in self.login_indicators)

            if is_login_page and 'password' in html_lc:
                for creds in self.default_creds:
                    user, pwd = creds.get('user'), creds.get('pass')
                    if not user or not pwd:
                        continue

                    try:
                        login_resp = self.session.post(url, data={'username': user, 'password': pwd}, timeout=10)
                        login_html_lc = login_resp.text.lower()
                        if any(indicator in login_html_lc for indicator in self.success_indicators):
                            vulns.append(Vulnerability(
                                type='Broken Authentication',
                                subcategory='Weak Credentials',
                                url=url,
                                details={
                                    'issue': 'Default or common credential accepted.',
                                    'username': user,
                                    'password': pwd
                                },
                                severity='High'
                            ))
                            break
                    except requests.RequestException:
                        continue

            # Test 2: Sensitive authentication endpoint exposure
            if any(keyword in url_lc for keyword in self.sensitive_keywords):
                vulns.append(Vulnerability(
                    type='Broken Authentication',
                    subcategory='Sensitive Endpoint Exposure',
                    url=url,
                    details={'issue': f'A sensitive authentication-related endpoint was found: {url}'},
                    severity='Medium'
                ))

            # Test 3: Insecure session cookie flags
            cookies = resp.headers.get('Set-Cookie', '')
            if 'session' in cookies.lower():
                if 'secure' not in cookies.lower() or 'httponly' not in cookies.lower():
                    vulns.append(Vulnerability(
                        type='Broken Authentication',
                        subcategory='Session Management',
                        url=url,
                        details={
                            'issue': 'Session cookie is missing recommended security flags (Secure, HttpOnly).',
                            'cookie': cookies
                        },
                        severity='Medium'
                    ))

        except Exception:
            pass

        return vulns