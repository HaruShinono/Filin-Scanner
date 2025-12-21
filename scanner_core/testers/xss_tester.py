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

                    # Quick check: Is the payload reflected at all?
                    if payload in resp.text:
                        # VERIFY LOGIC: Parse HTML to ensure it's in an executable context
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        if self._verify_execution_context(soup, payload):
                            return Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='Reflected XSS',
                                url=test_url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Payload was reflected in an executable HTML context (script, event handler, or raw HTML).'
                                },
                                severity='High'
                            )
                except requests.RequestException:
                    continue
                finally:
                    query_params[param] = original_value

        return None

    def _verify_execution_context(self, soup: BeautifulSoup, payload: str) -> bool:
        """
        Verifies if the reflected payload is actually executable.
        """
        payload_str = str(payload)

        # 1. Check for Safe Tags (textarea, title, code, etc.)
        # If the payload is strictly inside these tags, it won't execute.
        safe_tags = ['textarea', 'title', 'pre', 'code', 'xmp', 'noembed', 'noframes', 'style']
        for tag in safe_tags:
            for element in soup.find_all(tag):
                if element.string and payload_str in element.string:
                    return False

                    # 2. Check Script Context
        for script in soup.find_all('script'):
            if script.string and payload_str in script.string:
                # If inside quotes, it might be safe (simplified check)
                # Ideally, a JS parser is needed, but this catches basic string literals
                if f'"{payload_str}"' in script.string or f"'{payload_str}'" in script.string:
                    return False
                return True

                # 3. Check Attribute Context (Event Handlers)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower().startswith('on'):
                    # If payload is injected into an event handler
                    if isinstance(value, str) and payload_str in value:
                        return True
                    elif isinstance(value, list) and any(payload_str in v for v in value):
                        return True

        # 4. Check HTML Context (Injection of new tags)
        # If the payload starts with < and ends with >, check if it breaks out as raw HTML
        # Because BS4 parses the broken HTML, we check if the raw payload exists in the string representation
        # excluding the safe tags checked above.
        if payload_str.startswith('<') and payload_str in str(soup):
            return True

        return False