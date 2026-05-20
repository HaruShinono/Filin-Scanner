import re
from typing import List
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester
from integrations.retirejs_provider import get_retirejs_database, check_library_vulnerabilities


class OutdatedComponentTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.retire_db = get_retirejs_database().get('js', {})

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        try:
            resp = self.fetch(url)
            if not resp or 'text/html' not in resp.headers.get('Content-Type', '').lower():
                return vulns

            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', src=True)

            processed_scripts = set()

            for script in scripts:
                script_src = script.get('src')
                if not script_src:
                    continue

                full_script_url = urljoin(url, script_src)
                if full_script_url in processed_scripts:
                    continue
                processed_scripts.add(full_script_url)

                for lib_name, lib_data in self.retire_db.items():
                    extractors = lib_data.get('extractors', {})
                    detected_version = None

                    uri_regexes = extractors.get('uri', []) + extractors.get('filename', [])
                    for regex in uri_regexes:
                        try:
                            match = re.search(regex, full_script_url)
                            if match:
                                if match.groups():
                                    detected_version = match.group(1)
                                break
                        except re.error:
                            continue

                    if detected_version:
                        known_vulns = check_library_vulnerabilities(detected_version, lib_data)
                        if known_vulns:
                            highest_severity = self._calculate_highest_severity(known_vulns)
                            vulns.append(self._create_vulnerability_object(
                                url, lib_name, detected_version, full_script_url, known_vulns, highest_severity
                            ))
                            break

        except Exception:
            pass

        return vulns

    def _calculate_highest_severity(self, known_vulns: list) -> str:
        severities = [v.get('severity', 'low').lower() for v in known_vulns]
        if 'critical' in severities: return 'Critical'
        if 'high' in severities: return 'High'
        if 'medium' in severities: return 'Medium'
        return 'Low'

    def _create_vulnerability_object(self, page_url, lib_name, version, resource_url, vulns_list, severity):
        details = {
            'library': lib_name,
            'version': version,
            'resource_url': resource_url,
            'vulnerabilities_found': []
        }
        for v in vulns_list:
            cve = v.get('identifiers', {}).get('CVE', [])
            summary = v.get('identifiers', {}).get('summary', '')
            details['vulnerabilities_found'].append({
                'cve': cve[0] if cve else 'N/A',
                'summary': summary,
                'info_links': v.get('info', [])
            })

        return Vulnerability(
            type='Using Components with Known Vulnerabilities',
            subcategory=f'{lib_name.title()} {version}',
            url=page_url,
            details=details,
            severity=severity
        )