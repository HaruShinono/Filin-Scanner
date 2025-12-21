import random
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class LfiTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])
        self.indicators = self.config.get('indicators', [])

    def _determine_subcategory(self, payload: str) -> str:
        if 'etc/passwd' in payload or 'shadow' in payload:
            return 'Path Traversal'
        if 'boot.ini' in payload or 'win.ini' in payload:
            return 'Windows File Inclusion'
        if '/proc/self/environ' in payload:
            return 'ProcFS File Inclusion'
        return 'Generic File Inclusion'

    def test(self, url: str) -> Optional[Vulnerability]:
        parsed_url = urlparse(url)
        if not parsed_url.query or not self.payloads:
            return None

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = payload

                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    # If indicators are found in the response
                    if resp and any(indicator.lower() in resp.text.lower() for indicator in self.indicators):

                        # --- VERIFY LOGIC ---
                        # Create a fake payload: e.g., ../../../../etc/passwd -> ../../../../etc/NON_EXISTENT_FILE_1234
                        # If this fake file also returns the indicator (e.g. "root:x:0:0"),
                        # it means the website is just mirroring input or has static content -> False Positive.

                        fake_file = f"non_existent_file_{random.randint(1000, 9999)}"

                        if "win.ini" in payload:
                            verify_payload = payload.replace("win.ini", fake_file)
                        elif "passwd" in payload:
                            verify_payload = payload.replace("passwd", fake_file)
                        elif "shadow" in payload:
                            verify_payload = payload.replace("shadow", fake_file)
                        elif "boot.ini" in payload:
                            verify_payload = payload.replace("boot.ini", fake_file)
                        elif "environ" in payload:
                            verify_payload = payload.replace("environ", fake_file)
                        else:
                            # Fallback: append random string
                            verify_payload = payload + fake_file

                        verify_params = test_params.copy()
                        verify_params[param] = verify_payload
                        verify_url = urlunparse(parsed_url._replace(query=urlencode(verify_params, doseq=True)))

                        # Fetch verification response (bypass cache)
                        verify_resp = self.session.get(verify_url, timeout=10, verify=False)

                        # Check if indicators persist in the verification response
                        has_indicator_verify = False
                        if verify_resp:
                            has_indicator_verify = any(
                                ind.lower() in verify_resp.text.lower() for ind in self.indicators)

                        # Condition: Indicator present in Attack Response AND Absent in Verify Response
                        if not has_indicator_verify:
                            subcategory = self._determine_subcategory(payload)
                            return Vulnerability(
                                type='Local File Inclusion',
                                subcategory=subcategory,
                                url=test_url,
                                details={
                                    'parameter': param,
                                    'payload': payload,
                                    'control_payload': verify_payload,
                                    'evidence': 'Sensitive content found with payload but disappeared with control payload.'
                                },
                                severity='High'
                            )
                        # Else: Both have indicators -> False Positive

                except requests.RequestException:
                    continue

        return None