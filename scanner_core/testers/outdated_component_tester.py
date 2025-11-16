import re
from typing import List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class OutdatedComponentTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.libraries_to_check = self.config.get('libraries', [])

    def _normalize_version(self, version_str: str) -> List[int]:
        try:
            return [int(part) for part in re.findall(r'\d+', version_str)]
        except (ValueError, TypeError):
            return []

    def _is_outdated(self, current_version_str: str, latest_version_str: str) -> bool:
        current_normalized = self._normalize_version(current_version_str)
        latest_normalized = self._normalize_version(latest_version_str)

        if not current_normalized or not latest_normalized:
            return False

        # Pad shorter version list with zeros for comparison
        max_len = max(len(current_normalized), len(latest_normalized))
        current_normalized.extend([0] * (max_len - len(current_normalized)))
        latest_normalized.extend([0] * (max_len - len(latest_normalized)))

        return current_normalized < latest_normalized

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp or 'text/html' not in resp.headers.get('Content-Type', '').lower():
                return vulns

            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', src=True)

            for script in scripts:
                script_src = script.get('src')
                if not script_src:
                    continue

                full_script_url = urljoin(url, script_src)

                try:
                    js_resp = self.fetch(full_script_url)
                    if not js_resp or js_resp.status_code != 200:
                        continue

                    # Read only the first few KB to be efficient
                    content_head = js_resp.text[:5000]

                    for lib in self.libraries_to_check:
                        lib_name = lib.get('name')
                        lib_regex = lib.get('regex')
                        lib_latest = lib.get('latest')

                        if not all([lib_name, lib_regex, lib_latest]):
                            continue

                        match = re.search(lib_regex, content_head, re.IGNORECASE)
                        if match:
                            detected_version = match.group(1)
                            if self._is_outdated(detected_version, lib_latest):
                                vulns.append(Vulnerability(
                                    type='Using Components with Known Vulnerabilities',
                                    subcategory='Outdated Library',
                                    url=url,
                                    details={
                                        'library': lib_name,
                                        'detected_version': detected_version,
                                        'latest_version': lib_latest,
                                        'resource_url': full_script_url
                                    },
                                    severity='Medium'
                                ))
                            break  # Assume one file contains only one library

                except requests.RequestException:
                    continue

        except Exception:
            pass

        return vulns