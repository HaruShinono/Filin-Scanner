from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests
from bs4 import BeautifulSoup

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class XssTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])

    def test(self, url: str) -> Optional[Vulnerability]:
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return None

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            original_value = query_params[param]
            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    if not resp or resp.status_code != 200:
                        continue

                    # Check for basic reflection first
                    if payload in resp.text:
                        # More thorough check to see if it's in a dangerous context
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        if self._is_in_dangerous_context(soup, payload):
                            return Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='Reflected XSS',
                                url=test_url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'The payload was reflected in a potentially executable context in the HTML response.'
                                },
                                severity='High'
                            )
                except requests.RequestException:
                    continue
                finally:
                    query_params[param] = original_value

        return None

    def _is_in_dangerous_context(self, soup: BeautifulSoup, payload: str) -> bool:
        # Check if payload is inside a <script> tag (but not as a string literal)
        for tag in soup.find_all('script'):
            if tag.string and payload in tag.string:
                # Basic check to avoid flagging json/string data
                if not (tag.string.strip().startswith(('"', "'", '{', '['))):
                    return True

        # Check if payload is in an event handler attribute (e.g., onload, onerror)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower().startswith('on') and isinstance(value, str) and payload in value:
                    return True

        # Check for cases like <img src="[payload]"> which won't be caught by the above
        # This is a heuristic; a full check would require a browser context (DOM XSS)
        # For simplicity, we consider direct reflection of tags as dangerous
        if payload.startswith('<') and payload.endswith('>') and payload in str(soup):
            return True

        return False