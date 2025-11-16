from typing import List
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class IntegrityTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.trusted_domains = self.config.get('trusted_domains', [])

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp or 'text/html' not in resp.headers.get('Content-Type', '').lower():
                return vulns

            soup = BeautifulSoup(resp.text, 'html.parser')
            page_domain = urlparse(url).netloc

            for tag in soup.find_all('script', src=True):
                src = tag.get('src', '').strip()
                if not src:
                    continue

                parsed_src = urlparse(src)

                # Test 1: Mixed Content (insecure script on secure page)
                if url.startswith('https://') and src.startswith('http://'):
                    vulns.append(Vulnerability(
                        type='Software and Data Integrity Failure',
                        subcategory='Mixed Content',
                        url=url,
                        details={
                            'resource_url': src,
                            'issue': 'An insecure HTTP script was loaded on an HTTPS page.'
                        },
                        severity='High'
                    ))

                # Test 2: Subresource Integrity (SRI) missing
                is_cross_origin = parsed_src.netloc and parsed_src.netloc != page_domain
                if is_cross_origin and 'integrity' not in tag.attrs:
                    is_trusted = any(trusted in parsed_src.netloc for trusted in self.trusted_domains)
                    severity = 'Medium' if is_trusted else 'High'

                    vulns.append(Vulnerability(
                        type='Software and Data Integrity Failure',
                        subcategory='Missing Subresource Integrity',
                        url=url,
                        details={
                            'resource_url': src,
                            'issue': 'A third-party script is loaded without an integrity attribute.',
                            'is_trusted_cdn': is_trusted
                        },
                        severity=severity
                    ))

        except requests.RequestException:
            pass
        except Exception:  # Catch potential BeautifulSoup errors
            pass

        return vulns