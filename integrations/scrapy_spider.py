import scrapy
from urllib.parse import urlparse, urljoin
import re


class SmartSpider(scrapy.Spider):
    name = 'smart_spider'

    # Danh sách các đuôi file bỏ qua để tăng tốc độ quét và giảm rác
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

        # --- CẤU HÌNH CÀN QUÉT TỐI ĐA ---
        self.custom_settings = {
            'DEPTH_LIMIT': int(depth_limit),
            'ROBOTSTXT_OBEY': False,  # Không tuân thủ robots.txt (để quét sâu)
            'HTTPERROR_ALLOW_ALL': True,  # Thu thập cả link 403, 404, 500
            'LOG_LEVEL': 'ERROR',  # Tắt log rác
            'CONCURRENT_REQUESTS': 32,  # Tăng tốc độ luồng
            'DOWNLOAD_DELAY': 0.1,  # Chờ nhẹ để tránh sập server
            'RETRY_ENABLED': True,
            'RETRY_TIMES': 2,
            'COOKIES_ENABLED': True,
            'AJAXCRAWL_ENABLED': True,  # Hỗ trợ crawl _escaped_fragment_
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'DEFAULT_REQUEST_HEADERS': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'ngrok-skip-browser-warning': 'true'  # Bypass Ngrok
            }
        }

        # Parse Cookies và Header Authentication
        self.cookies_dict = {}
        self.auth_headers = {}
        if auth_cookies:
            for item in auth_cookies.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    self.cookies_dict[k] = v
                    # Auto-detect JWT/Bearer token
                    if k.lower() in ['token', 'jwt', 'bearer', 'authorization'] or v.startswith('eyJ'):
                        self.auth_headers['Authorization'] = f'Bearer {v}'

    def start_requests(self):
        headers = self.custom_settings['DEFAULT_REQUEST_HEADERS'].copy()
        headers.update(self.auth_headers)

        for url in self.start_urls:
            # 1. Quét URL gốc
            yield scrapy.Request(url, cookies=self.cookies_dict, headers=headers, callback=self.parse)

            # 2. PROACTIVE DISCOVERY: Cố tình quét robots.txt và sitemap.xml
            yield scrapy.Request(urljoin(self.base_url, '/robots.txt'), cookies=self.cookies_dict, headers=headers,
                                 callback=self.parse_robots)
            yield scrapy.Request(urljoin(self.base_url, '/sitemap.xml'), cookies=self.cookies_dict, headers=headers,
                                 callback=self.parse_sitemap)

    def _is_valid_extension(self, url: str) -> bool:
        """Kiểm tra xem URL có trỏ đến file rác (ảnh, video) không"""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return not any(path_lower.endswith(ext) for ext in self.IGNORED_EXTENSIONS)

    def parse(self, response):
        """Phân tích HTML và điều hướng"""
        if self._is_valid_extension(response.url):
            yield {'type': 'url', 'url': response.url}  # Thêm nhãn type cho URL

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

            # 2. [CỰC KỲ QUAN TRỌNG] TRÍCH XUẤT FULL FORM DATA
            for form in response.xpath('//form'):
                action = form.attrib.get('action', '')
                # Xử lý nếu action rỗng (tức là submit vào chính trang hiện tại)
                full_form_url = response.urljoin(action) if action else response.url

                method = form.attrib.get('method', 'get').upper()

                inputs = []
                # Lấy tất cả input, textarea, select
                for input_field in form.xpath('.//input | .//textarea | .//select'):
                    name = input_field.attrib.get('name')
                    if name:
                        inputs.append({
                            'name': name,
                            'type': input_field.attrib.get('type', 'text'),
                            'value': input_field.attrib.get('value', '')  # Lấy value mặc định (như CSRF token)
                        })

                # Gửi thông tin Form cực chi tiết về cho hệ thống
                yield {
                    'type': 'form',
                    'url': full_form_url,
                    'method': method,
                    'inputs': inputs,
                    'page_found': response.url
                }

            # 3. Tìm JS (giữ nguyên)
            js_files = response.css('script::attr(src)').getall()
            for js in js_files:
                if not js.startswith(('http', '/')): continue
                yield response.follow(js, self.parse_js, cookies=self.cookies_dict, headers=headers)

    def parse_js(self, response):
        """Phân tích file JS"""
        if self._is_valid_extension(response.url):
            yield {'type': 'url', 'url': response.url}

        body = response.text

        # 1. Regex SIÊU CẤP bắt REST API, GraphQL, Webhooks (bao gồm cả params)
        # Bắt: /api/v1/users?id=1, https://api.site.com/graphql, /rest/products/search
        api_pattern = r'["\']((?:/|https?://)[a-zA-Z0-9_.-]+(?:/(?:api|rest|graphql|v1|v2|b2b|assets|ftp|users|products)[a-zA-Z0-9_.-]*)+(?:\?[a-zA-Z0-9_.-]+=[^"\']*)?)["\']'
        api_endpoints = re.findall(api_pattern, body)

        for ep in api_endpoints:
            full_api_url = response.urljoin(ep)
            if self._is_valid_extension(full_api_url):
                yield {'url': full_api_url}
                # Thử follow API nếu nó nằm trên cùng domain
                if urlparse(full_api_url).netloc == self.allowed_domains[0]:
                    headers = self.custom_settings['DEFAULT_REQUEST_HEADERS'].copy()
                    headers.update(self.auth_headers)
                    yield response.follow(full_api_url, self.parse, cookies=self.cookies_dict, headers=headers)

        # 2. Đọc cấu hình Route của SPA (Angular/React Router)
        spa_routes = re.findall(r'path\s*:\s*[\'"]([a-zA-Z0-9_/-]+)[\'"]', body)
        for route in spa_routes:
            if route not in ['**', '', '404']:
                spa_full_url = f"{self.base_url}/#/{route.lstrip('/')}"
                yield {'url': spa_full_url}

    def parse_robots(self, response):
        """Đọc robots.txt để lôi ra các đường dẫn bị cấm (Disallow)"""
        if response.status != 200: return

        body = response.text
        # Tìm tất cả Disallow và Allow paths
        paths = re.findall(r'(?:Disallow|Allow):\s*(/[^\s]+)', body, re.IGNORECASE)

        for path in paths:
            full_url = response.urljoin(path)
            if self._is_valid_extension(full_url):
                yield {'url': full_url}
                # Đi sâu vào đường dẫn cấm
                headers = self.custom_settings['DEFAULT_REQUEST_HEADERS'].copy()
                headers.update(self.auth_headers)
                yield response.follow(full_url, self.parse, cookies=self.cookies_dict, headers=headers)

    def parse_sitemap(self, response):
        """Đọc sitemap.xml để lấy toàn bộ bản đồ trang"""
        if response.status != 200: return

        # Sitemap có thể là XML
        links = response.css('loc::text').getall()
        for link in links:
            if self._is_valid_extension(link):
                yield {'url': link}
                headers = self.custom_settings['DEFAULT_REQUEST_HEADERS'].copy()
                headers.update(self.auth_headers)
                yield response.follow(link, self.parse, cookies=self.cookies_dict, headers=headers)