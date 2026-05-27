# Mở scanner_core/testers/xss_tester.py, thay thế hàm test_form bằng đoạn này:

def test_form(self, form_data: dict) -> Optional[Vulnerability]:
    """Kiểm tra XSS trên Form và JSON API"""
    url = form_data['url']
    method = form_data.get('method', 'POST').upper()
    inputs = form_data.get('inputs', [])
    is_api = form_data.get('is_api', False)

    for target_input in inputs:
        param = target_input['name']

        for payload in self.payloads:
            try:
                resp = self._inject_form_payload(url, method, inputs, param, payload, is_api)
                if not resp: continue

                content_type = resp.headers.get('Content-Type', '').lower()

                # Nếu payload không được server trả về, bỏ qua
                if payload not in resp.text:
                    continue

                # 1. Nếu phản hồi là JSON (Juice Shop Search API)
                if 'json' in content_type:
                    return Vulnerability(
                        type='Cross-Site Scripting (XSS)', subcategory=f'API Reflected XSS ({method})', url=url,
                        details={
                            'parameter': param, 'payload': payload,
                            'evidence': 'Unescaped payload reflected directly in JSON API response. This causes DOM XSS if rendered unsafely.'
                        },
                        severity='High'
                    )

                # 2. Nếu phản hồi là HTML (Web truyền thống)
                elif 'html' in content_type:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    if self._verify_execution_context(soup, payload):
                        return Vulnerability(
                            type='Cross-Site Scripting (XSS)', subcategory=f'Stored/Reflected XSS ({method})', url=url,
                            details={'parameter': param, 'payload': payload,
                                     'evidence': 'Payload reflected in executable HTML context.'},
                            severity='High'
                        )
            except Exception:
                continue
    return None


def _inject_form_payload(self, url, method, inputs, target_param, payload, is_api):
    data = {}
    for inp in inputs:
        data[inp['name']] = payload if inp['name'] == target_param else inp.get('value', 'test')

    headers = {'ngrok-skip-browser-warning': 'true'}
    try:
        if method == 'GET':
            return self.session.get(url, params=data, timeout=10, verify=False, headers=headers)
        if is_api or 'api' in url.lower():
            return self.session.post(url, json=data, timeout=10, verify=False, headers=headers)
        else:
            return self.session.post(url, data=data, timeout=10, verify=False, headers=headers)
    except Exception:
        return None