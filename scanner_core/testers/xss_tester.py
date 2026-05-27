from typing import Optional, List
import traceback
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import requests
from bs4 import BeautifulSoup

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class XssTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return vulns

        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.fetch(test_url)
                    if not resp: continue

                    content_type = resp.headers.get('Content-Type', '').lower()

                    if payload in resp.text:
                        if 'application/json' in content_type:
                            vulns.append(Vulnerability(
                                type='Cross-Site Scripting (XSS)', subcategory='API Reflected XSS', url=test_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Unescaped payload reflected directly in JSON API response.'},
                                severity='High'
                            ))
                            break
                        elif 'text/html' in content_type:
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            if self._verify_execution_context(soup, payload):
                                vulns.append(Vulnerability(
                                    type='Cross-Site Scripting (XSS)', subcategory='Reflected XSS', url=test_url,
                                    details={'parameter': param, 'payload': payload,
                                             'evidence': 'Payload reflected in executable HTML context.'},
                                    severity='High'
                                ))
                                break
                except requests.RequestException:
                    continue
        return vulns

    def test_form(self, form_data: dict) -> List[Vulnerability]:
        vulns = []
        try:
            url = form_data['url']
            method = form_data.get('method', 'POST').upper()
            inputs = form_data.get('inputs', [])
            is_api = form_data.get('is_api', False) or any(
                k in url.lower() for k in ['/api/', '/rest/', '/v1/', '/v2/'])

            print(f"  [DEBUG-XSS] Analyzing Endpoint: {method} {url} (Is API: {is_api})", flush=True)

            for target_input in inputs:
                if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']:
                    continue

                param = target_input['name']

                for payload in self.payloads:
                    print(f"  [DEBUG-XSS] Testing Param [{param}] with Payload: {payload[:50]}...", flush=True)
                    try:
                        resp = self._inject_form_payload(url, method, inputs, param, payload, is_api)
                        if not resp:
                            continue

                        content_type = resp.headers.get('Content-Type', '').lower()

                        if payload in resp.text:
                            print(f"  [DEBUG-XSS] Payload REFLECTED in response body! Content-Type: {content_type}",
                                  flush=True)

                            if 'json' in content_type:
                                print(f"  [DEBUG-XSS] !!! API XSS SUCCESS !!!", flush=True)
                                vulns.append(Vulnerability(
                                    type='Cross-Site Scripting (XSS)', subcategory=f'API Reflected XSS ({method})',
                                    url=url,
                                    details={'parameter': f"Body/Query: {param}", 'payload': payload,
                                             'evidence': 'Unescaped payload reflected directly in JSON API response. This causes DOM XSS if rendered unsafely.'},
                                    severity='High'
                                ))
                                break
                            elif 'text/html' in content_type:
                                soup = BeautifulSoup(resp.text, 'html.parser')
                                is_executable = self._verify_execution_context(soup, payload)
                                print(f"  [DEBUG-XSS] Context analysis: Is Executable = {is_executable}", flush=True)

                                if is_executable:
                                    print(f"  [DEBUG-XSS] !!! HTML XSS SUCCESS !!!", flush=True)
                                    vulns.append(Vulnerability(
                                        type='Cross-Site Scripting (XSS)',
                                        subcategory=f'Stored/Reflected XSS ({method})', url=url,
                                        details={'parameter': f"Form Field: {param}", 'payload': payload,
                                                 'evidence': 'Payload reflected in executable HTML context.'},
                                        severity='High'
                                    ))
                                    break
                    except requests.RequestException as e:
                        print(f"  [DEBUG-XSS] Request error: {e}", flush=True)
        except Exception as e:
            print(f"  [DEBUG-XSS-CRASH] Exception in test_form: {e}", flush=True)
            traceback.print_exc()

        return vulns

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False):
        data = {}
        for inp in inputs:
            data[inp['name']] = payload if inp['name'] == target_param else inp.get('value', 'test')

        headers = {'ngrok-skip-browser-warning': 'true'}
        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)
            if is_api or 'api' in url.lower():
                headers['Content-Type'] = 'application/json'
                headers['Accept'] = 'application/json'
                return self.session.post(url, json=data, timeout=10, verify=False, headers=headers)
            else:
                return self.session.post(url, data=data, timeout=10, verify=False, headers=headers)
        except Exception:
            return None

    def _verify_execution_context(self, soup: BeautifulSoup, payload: str) -> bool:
        payload_str = str(payload)
        safe_tags = ['textarea', 'title', 'pre', 'code', 'xmp', 'noembed', 'noframes', 'style']
        for tag in safe_tags:
            for element in soup.find_all(tag):
                if element.string and payload_str in element.string: return False

        for script in soup.find_all('script'):
            if script.string and payload_str in script.string:
                if f'"{payload_str}"' in script.string or f"'{payload_str}'" in script.string:
                    if not any(c in payload_str for c in ["'", '"']): return False
                return True

        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower().startswith('on'):
                    if isinstance(value, str) and payload_str in value:
                        return True
                    elif isinstance(value, list) and any(payload_str in v for v in value):
                        return True

        if payload_str.startswith('<') and payload_str in str(soup): return True
        return False