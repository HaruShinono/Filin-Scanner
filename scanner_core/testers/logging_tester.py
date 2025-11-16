import re
from typing import List
from urllib.parse import urlparse, urljoin

import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class LoggingTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.log_paths = self.config.get('paths', [])
        self.sensitive_patterns = self.config.get('sensitive_patterns', [])
        self.debug_keywords = self.config.get('debug_keywords', [])

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if not self.log_paths:
            return vulns

        for path in self.log_paths:
            test_url = urljoin(base_url, path)
            try:
                resp = self.fetch(test_url, allow_redirects=False)
                if not resp or resp.status_code != 200 or not resp.text:
                    continue

                content = resp.text
                content_lower = content.lower()
                found_sensitive = False

                for pattern_config in self.sensitive_patterns:
                    pattern = pattern_config.get('regex')
                    description = pattern_config.get('description')
                    if not pattern:
                        continue

                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        found_sensitive = True
                        vulns.append(Vulnerability(
                            type='Security Logging and Monitoring Failure',
                            subcategory='Sensitive Data in Logs',
                            url=test_url,
                            details={
                                'description': description,
                                'match': match.group(0)[:100],  # Truncate match
                                'log_path': path
                            },
                            severity='High'
                        ))
                        break

                if not found_sensitive:
                    if any(keyword in content_lower for keyword in self.debug_keywords):
                        vulns.append(Vulnerability(
                            type='Security Logging and Monitoring Failure',
                            subcategory='Exposed Debug Information',
                            url=test_url,
                            details={
                                'issue': 'The log file appears to contain debug or stack trace information.',
                                'log_path': path
                            },
                            severity='Medium'
                        ))
                    else:
                        vulns.append(Vulnerability(
                            type='Security Logging and Monitoring Failure',
                            subcategory='Accessible Log File',
                            url=test_url,
                            details={
                                'issue': 'A potentially sensitive log file was found to be publicly accessible.',
                                'log_path': path
                            },
                            severity='Low'
                        ))

            except requests.RequestException:
                continue

        return vulns