from typing import Optional
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class XxeTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])
        self.indicators = self.config.get('indicators', [])
        self.endpoint_keywords = self.config.get('endpoint_keywords', [])

    def _is_potential_xml_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in self.endpoint_keywords)

    def test(self, url: str) -> Optional[Vulnerability]:
        if not self._is_potential_xml_endpoint(url):
            return None

        headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml, text/xml, */*'
        }

        for payload_config in self.payloads:
            payload = payload_config.get('payload')
            subcategory = payload_config.get('subcategory', 'Generic XXE')
            if not payload:
                continue

            try:
                # Use a direct POST request instead of the GET-based fetch method
                response = self.session.post(
                    url,
                    data=payload.encode('utf-8'),
                    headers=headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=False
                )

                if response and any(indicator.lower() in response.text.lower() for indicator in self.indicators):
                    return Vulnerability(
                        type='XML External Entity (XXE)',
                        subcategory=subcategory,
                        url=url,
                        details={
                            'payload': payload,
                            'evidence': 'A known indicator string was found in the server response.'
                        },
                        severity='Critical'
                    )
            except requests.RequestException:
                continue

        return None