import scrapy
from urllib.parse import urlparse
import re


class SmartSpider(scrapy.Spider):
    name = 'smart_spider'

    IGNORED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
        '.mp4', '.avi', '.mov', '.mp3', '.wav', '.flac',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.exe', '.dmg', '.iso',
        '.woff', '.woff2', '.ttf', '.eot', '.css'
    }

    def __init__(self, target='', depth_limit=2, auth_cookies='', *args, **kwargs):
        super(SmartSpider, self).__init__(*args, **kwargs)
        self.start_urls = [target]
        self.allowed_domains = [urlparse(target).netloc]
        self.base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        self.custom_settings = {
            'DEPTH_LIMIT': int(depth_limit),
            'ROBOTSTXT_OBEY': False,
            'HTTPERROR_ALLOW_ALL': True,
            'LOG_LEVEL': 'ERROR',
            'CONCURRENT_REQUESTS': 32,
            'DOWNLOAD_DELAY': 0.1,
            'RETRY_ENABLED': True,
            'RETRY_TIMES': 2,
            'COOKIES_ENABLED': True,
            'AJAXCRAWL_ENABLED': True,
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'DEFAULT_REQUEST_HEADERS': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'ngrok-skip-browser-warning': 'true'
            }
        }

        self.cookies_dict = {}
        self.auth_headers = {}
        if auth_cookies:
            for item in auth_cookies.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    self.cookies_dict[k] = v
                    if k.lower() in ['token', 'jwt', 'bearer', 'authorization'] or v.startswith('eyJ'):
                        self.auth_headers['Authorization'] = f'Bearer {v}'

    def start_requests(self):
        headers = self.custom_settings['DEFAULT_REQUEST_HEADERS'].copy()
        headers.update(self.auth_headers)

        for url in self.start_urls:
            yield scrapy.Request(url, cookies=self.cookies_dict, headers=headers, callback=self.parse)
            yield scrapy.Request(urljoin(self.base_url, '/robots.txt'), cookies=self.cookies_dict, headers=headers,
                                 callback=self.parse_robots)
            yield scrapy.Request(urljoin(self.base_url, '/sitemap.xml'), cookies=self.cookies_dict, headers=headers,
                                 callback=self.parse_sitemap)

    def _is_valid_extension(self, url: str) -> bool:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return not any(path_lower.endswith(ext) for ext in self.IGNORED_EXTENSIONS)

    def parse(self, response):
        if self._is_valid_extension(response.url):
            yield {'type': 'url', 'url': response.url}

        headers = self.custom_settings['DEFAULT_REQUEST_HEADERS'].copy()
        headers.update(self.auth_headers)
        content_type = response.headers.get('Content-Type', b'').decode('utf-8').lower()

        if 'text/html' in content_type:
            # 1. Trích xuất Links
            links = response.css('a::attr(href), iframe::attr(src)').getall()
            for link in links:
                if link.startswith(('javascript:', 'mailto:', 'tel:')): continue
                if '#' in link:
                    full_spa_url = response.urljoin(link)
                    if self._is_valid_extension(full_spa_url):
                        yield {'type': 'url', 'url': full_spa_url}
                    continue
                if self._is_valid_extension(link):
                    yield response.follow(link, self.parse, cookies=self.cookies_dict, headers=headers)

            # 2. Trích xuất HTML Forms (Dành cho web truyền thống)
            for form in response.xpath('//form'):
                action = form.attrib.get('action', '')
                full_form_url = response.urljoin(action) if action else response.url
                method = form.attrib.get('method', 'get').upper()

                inputs = []
                for input_field in form.xpath('.//input | .//textarea | .//select'):
                    # Hỗ trợ cả name của HTML5 và formControlName của Angular
                    name = input_field.attrib.get('name') or input_field.attrib.get('id') or input_field.attrib.get(
                        'formcontrolname')
                    if name:
                        inputs.append({
                            'name': name,
                            'type': input_field.attrib.get('type', 'text'),
                            'value': input_field.attrib.get('value', 'test')
                        })

                if inputs:
                    yield {
                        'type': 'form', 'url': full_form_url, 'method': method,
                        'inputs': inputs, 'page_found': response.url, 'is_api': False
                    }

            # 3. Tìm JS file
            js_files = response.css('script::attr(src)').getall()
            for js in js_files:
                if not js.startswith(('http', '/')): continue
                yield response.follow(js, self.parse_js, cookies=self.cookies_dict, headers=headers)

    def parse_js(self, response):
        """Đọc file JS, moi API và tạo 'Ghost Form' để Fuzzing"""
        if self._is_valid_extension(response.url):
            yield {'type': 'url', 'url': response.url}

        body = response.text

        # 1. Bắt REST API
        api_pattern = r'["\']((?:/|https?://)[a-zA-Z0-9_.-]+(?:/(?:api|rest|graphql|v1|v2|b2b|assets|ftp|users|products|login|admin)[a-zA-Z0-9_.-]*)+(?:\?[a-zA-Z0-9_.-]+=[^"\']*)?)["\']'
        api_endpoints = re.findall(api_pattern, body)

        for ep in api_endpoints:
            full_api_url = response.urljoin(ep)
            if self._is_valid_extension(full_api_url):
                yield {'type': 'url', 'url': full_api_url}

                # --- [TÍNH NĂNG MỚI] GHOST FORM GENERATOR ---
                # Nếu URL nhìn giống API Đăng nhập/Đăng ký
                ep_lower = ep.lower()
                if any(k in ep_lower for k in ['login', 'auth', 'signin', 'token']):
                    yield {
                        'type': 'form', 'url': full_api_url, 'method': 'POST', 'is_api': True,
                        'inputs': [{'name': 'email', 'value': 'admin@test.com', 'type': 'text'},
                                   {'name': 'password', 'value': '123456', 'type': 'password'}],
                        'page_found': response.url
                    }
                # Nếu URL nhìn giống API Tìm kiếm/Sản phẩm
                elif any(k in ep_lower for k in ['search', 'query', 'find', 'product']):
                    yield {
                        'type': 'form', 'url': full_api_url, 'method': 'GET', 'is_api': True,
                        'inputs': [{'name': 'q', 'value': 'apple', 'type': 'text'},
                                   {'name': 'id', 'value': '1', 'type': 'text'}],
                        'page_found': response.url
                    }
                # Nếu là API user/profile (thường dùng PUT/POST)
                elif any(k in ep_lower for k in ['user', 'profile', 'update']):
                    yield {
                        'type': 'form', 'url': full_api_url, 'method': 'PUT', 'is_api': True,
                        'inputs': [{'name': 'id', 'value': '1', 'type': 'text'},
                                   {'name': 'role', 'value': 'user', 'type': 'text'},
                                   {'name': 'email', 'value': 'test@test.com', 'type': 'text'}],
                        'page_found': response.url
                    }
                # --------------------------------------------

        # 2. Đọc cấu hình Route của SPA
        spa_routes = re.findall(r'path\s*:\s*[\'"]([a-zA-Z0-9_/-]+)[\'"]', body)
        for route in spa_routes:
            if route not in ['**', '', '404']:
                spa_full_url = f"{self.base_url}/#/{route.lstrip('/')}"
                yield {'type': 'url', 'url': spa_full_url}

    def parse_robots(self, response):
        if response.status != 200: return
        paths = re.findall(r'(?:Disallow|Allow):\s*(/[^\s]+)', response.text, re.IGNORECASE)
        for path in paths:
            full_url = response.urljoin(path)
            if self._is_valid_extension(full_url):
                yield {'type': 'url', 'url': full_url}

    def parse_sitemap(self, response):
        if response.status != 200: return
        links = response.css('loc::text').getall()
        for link in links:
            if self._is_valid_extension(link):
                yield {'type': 'url', 'url': link}