from typing import Optional
import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class Csrftester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.token_names = self.config.get('token_names', [])

    def test(self, url: str) -> Optional[Vulnerability]:
        try:
            resp = self.fetch(url)
            if not resp or 'text/html' not in resp.headers.get('Content-Type', '').lower():
                return None

            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                method = form.get('method', 'get').lower()
                if method != 'post':
                    continue

                inputs = form.find_all('input', {'type': 'hidden'})

                has_token = False
                for i in inputs:
                    input_name = i.get('name', '').lower()
                    if any(token_name in input_name for token_name in self.token_names):
                        has_token = True
                        break

                if not has_token:
                    set_cookie_header = resp.headers.get('Set-Cookie', '').lower()
                    has_samesite_policy = 'samesite=strict' in set_cookie_header or 'samesite=lax' in set_cookie_header

                    severity = 'Medium' if not has_samesite_policy else 'Low'

                    return Vulnerability(
                        type='Cross-Site Request Forgery (CSRF)',
                        subcategory='Missing Anti-CSRF Token',
                        url=url,
                        details={
                            'form_action': form.get('action', 'N/A'),
                            'evidence': 'A POST form was found without a recognizable anti-CSRF token.',
                            'cookie_samesite_policy_found': has_samesite_policy
                        },
                        severity=severity
                    )
        except Exception:
            return None

        return None