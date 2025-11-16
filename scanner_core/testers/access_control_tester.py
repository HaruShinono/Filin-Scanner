from typing import List
import requests
from urllib.parse import urlparse, urljoin

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class AccessControlTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.paths_to_test = self.config.get('paths', [])
        self.forbidden_keywords = self.config.get('forbidden_keywords', [])

    def _determine_subcategory(self, path: str) -> str:
        path = path.lower()
        if any(p in path for p in ['/../../', '/../', '/etc/', 'passwd']):
            return "Path Traversal"
        if any(p in path for p in ['.env', '.git', '/secrets', '/backup', '/uploads', '/env']):
            return "Sensitive File/Directory Exposure"
        if path.endswith('/'):
            return "Directory Listing"
        if any(p in path for p in ['account/', 'user/', '/basket/', '/feedback/', '/review/', '/files/']):
            return "Insecure Direct Object References (IDOR)"
        if 'admin' in path or 'config' in path or 'internal' in path:
            return "Privilege Escalation"
        return "Unauthenticated Access"

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if not self.paths_to_test:
            return vulns

        for path in self.paths_to_test:
            test_url = urljoin(base, path)

            try:
                resp = self.fetch(test_url, allow_redirects=False)
                if not resp:
                    continue

                if resp.status_code not in [200, 301, 302, 307]:
                    continue

                body = resp.text.lower()
                if any(keyword in body for keyword in self.forbidden_keywords):
                    continue

                location = resp.headers.get('Location', '').lower()
                if any(keyword in location for keyword in ['login', 'log in', 'signin', 'auth']):
                    continue

                if 'www-authenticate' in resp.headers:
                    continue

                subcategory = self._determine_subcategory(path)
                vulns.append(Vulnerability(
                    type='Broken Access Control',
                    subcategory=subcategory,
                    url=test_url,
                    details={
                        'status_code': resp.status_code,
                        'evidence': f'Path "{path}" was accessible without denial or login redirection.'
                    },
                    severity='High'
                ))
            except Exception:
                continue

        return vulns