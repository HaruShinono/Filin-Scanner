# utils/swagger_parser.py
import requests
import json
from urllib.parse import urljoin, urlparse


def discover_api_from_swagger(base_url, cookies=None):
    """Tìm và parse file swagger.json để bóc xuất toàn bộ API Form"""
    common_paths = [
        '/swagger.json', '/api/swagger.json', '/v2/api-docs', '/v3/api-docs',
        '/openapi.json', '/docs/swagger.json'
    ]

    headers = {'ngrok-skip-browser-warning': 'true'}
    cookie_dict = {}
    if cookies:
        for item in cookies.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookie_dict[k] = v

    discovered_forms = []

    for path in common_paths:
        target = urljoin(base_url, path)
        try:
            resp = requests.get(target, headers=headers, cookies=cookie_dict, timeout=5, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                if 'swagger' in data or 'openapi' in data:
                    print(f"  [API Discovery] Found Swagger Doc at {target}!", flush=True)

                    base_api_path = data.get('basePath', '')
                    paths = data.get('paths', {})

                    for endpoint, methods in paths.items():
                        for method_name, details in methods.items():
                            method = method_name.upper()
                            if method not in ['POST', 'PUT', 'GET', 'PATCH', 'DELETE']: continue

                            full_api_url = urljoin(base_url, base_api_path + endpoint)

                            inputs = []
                            # Parse parameters
                            for param in details.get('parameters', []):
                                inputs.append({
                                    'name': param.get('name', 'param'),
                                    'value': 'test_val',  # Default value
                                    'type': 'text'
                                })

                            discovered_forms.append({
                                'type': 'form',
                                'url': full_api_url,
                                'method': method,
                                'inputs': inputs,
                                'is_api': True
                            })
                    break  # Chỉ cần parse 1 file swagger là đủ
        except:
            pass

    return discovered_forms