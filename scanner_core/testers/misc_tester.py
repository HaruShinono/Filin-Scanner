from typing import List
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class MiscTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.error_keywords = self.config.get('error_keywords', [])
        self.security_policy_config = self.config.get('security_policy', {})
        self.privacy_policy_config = self.config.get('privacy_policy', {})
        self.scoreboard_config = self.config.get('scoreboard', {})
        self.chatbot_config = self.config.get('chatbot', {})

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp:
                return vulns

            url_lc = url.lower()
            html_lc = resp.text.lower()

            # Test 1: Error Handling / Debug Information Leak
            if any(keyword in html_lc for keyword in self.error_keywords):
                vulns.append(Vulnerability(
                    type='Security Misconfiguration',
                    subcategory='Improper Error Handling',
                    url=url,
                    details={'evidence': 'The response contains debug information or a stack trace.'},
                    severity='Medium'
                ))

            # Test 2: Security Policy Information Leak
            if any(keyword in url_lc for keyword in self.security_policy_config.get('path_keywords', [])):
                if any(term in html_lc for term in self.security_policy_config.get('sensitive_terms', [])):
                    vulns.append(Vulnerability(
                        type='Miscellaneous',
                        subcategory='Sensitive Info in Security Policy',
                        url=url,
                        details={
                            'evidence': 'Sensitive terms like "vulnerability" or "exploit" were found in a security documentation page.'},
                        severity='Low'
                    ))

            # Test 3: Privacy Policy Information Leak
            if any(keyword in url_lc for keyword in self.privacy_policy_config.get('path_keywords', [])):
                if any(term in html_lc for term in self.privacy_policy_config.get('sensitive_terms', [])):
                    vulns.append(Vulnerability(
                        type='Miscellaneous',
                        subcategory='Sensitive Info in Privacy Policy',
                        url=url,
                        details={
                            'evidence': 'Sensitive terms like "session id" or "token" were found in the privacy policy.'},
                        severity='Low'
                    ))

            # Test 4: Scoreboard Information Leak
            if any(keyword in url_lc for keyword in self.scoreboard_config.get('path_keywords', [])):
                if any(term in html_lc for term in self.scoreboard_config.get('content_keywords', [])):
                    vulns.append(Vulnerability(
                        type='Miscellaneous',
                        subcategory='Score Board Information Leak',
                        url=url,
                        details={
                            'evidence': 'A scoreboard page appears to contain administrative or sensitive information.'},
                        severity='Low'
                    ))

            # Test 5: Chatbot Manipulation Endpoint
            if any(keyword in url_lc for keyword in self.chatbot_config.get('path_keywords', [])):
                vulns.append(Vulnerability(
                    type='Miscellaneous',
                    subcategory='Chatbot Manipulation Endpoint',
                    url=url,
                    details={
                        'evidence': 'The URL suggests an endpoint for disabling or manipulating a chatbot system.'},
                    severity='Low'
                ))

        except requests.RequestException:
            pass

        return vulns