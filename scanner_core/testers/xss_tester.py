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
                            return Vulnerability(
                                type='Cross-Site Scripting (XSS)', subcategory='API Reflected XSS', url=test_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Unescaped payload reflected directly in JSON API response.'},
                                severity='High'
                            )
                        elif 'text/html' in content_type:
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            if self._verify_execution_context(soup, payload):
                                return Vulnerability(
                                    type='Cross-Site Scripting (XSS)', subcategory='Reflected XSS', url=test_url,
                                    details={'parameter': param, 'payload': payload,
                                             'evidence': 'Payload reflected in executable HTML context.'},
                                    severity='High'
                                )
                except requests.RequestException:
                    continue
        return None

    # --- [MỚI] HÀM KIỂM TRA FORM VÀ API CHO XSS ---
    def test_form(self, form_data: dict) -> Optional[Vulnerability]:
        url = form_data['url']
        method = form_data.get('method', 'POST').upper()
        inputs = form_data['inputs']
        is_api = form_data.get('is_api', False) or any(k in url.lower() for k in ['/api/', '/rest/', '/v1/'])

        for target_input in inputs:
            if target_input.get('type') in ['hidden', 'submit', 'radio', 'button']:
                continue

            param = target_input['name']

            for payload in self.payloads:
                try:
                    resp = self._inject_form_payload(url, method, inputs, param, payload, is_api)
                    if not resp: continue

                    content_type = resp.headers.get('Content-Type', '').lower()

                    if payload in resp.text:
                        if 'application/json' in content_type:
                            return Vulnerability(
                                type='Cross-Site Scripting (XSS)', subcategory='API Reflected XSS (POST/PUT)', url=url,
                                details={'parameter': f"Body/Query: {param}", 'payload': payload,
                                         'evidence': 'Unescaped payload reflected directly in JSON API response.'},
                                severity='High'
                            )
                        elif 'text/html' in content_type:
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            if self._verify_execution_context(soup, payload):
                                return Vulnerability(
                                    type='Cross-Site Scripting (XSS)', subcategory='Stored/Reflected XSS (Form)',
                                    url=url,
                                    details={'parameter': f"Form Field: {param}", 'payload': payload,
                                             'evidence': 'Payload reflected in executable HTML context.'},
                                    severity='High'
                                )
                except requests.RequestException:
                    pass
        return None

    def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api=False):
        data = {}
        for inp in inputs:
            if target_param and inp['name'] == target_param:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp.get('value', 'test')

        headers = {'ngrok-skip-browser-warning': 'true', 'Accept': 'application/json, text/plain, */*'}
        try:
            if method == 'GET':
                return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)
            if is_api:
                headers['Content-Type'] = 'application/json'
                if method == 'PUT': return self.session.put(url, json=data, timeout=10, verify=False, headers=headers)
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