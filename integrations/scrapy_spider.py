import scrapy
from urllib.parse import urlparse
import re


class SmartSpider(scrapy.Spider):
    name = 'smart_spider'

    def __init__(self, target='', depth_limit=2, auth_cookies='', *args, **kwargs):
        super(SmartSpider, self).__init__(*args, **kwargs)
        self.start_urls = [target]
        self.allowed_domains = [urlparse(target).netloc]

        self.custom_settings = {
            'DEPTH_LIMIT': int(depth_limit),
            'ROBOTSTXT_OBEY': False,
            'LOG_LEVEL': 'ERROR',
            'CONCURRENT_REQUESTS': 16,
            'DOWNLOAD_DELAY': 0.1,
            'COOKIES_ENABLED': True,
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        }

        self.cookies_dict = {}
        if auth_cookies:
            for item in auth_cookies.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    self.cookies_dict[k] = v

    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(url, cookies=self.cookies_dict, callback=self.parse)

    def parse(self, response):
        yield {'url': response.url}

        content_type = response.headers.get('Content-Type', b'').decode('utf-8').lower()

        if 'text/html' in content_type:
            # 1. Bắt các link truyền thống
            links = response.css('a::attr(href), form::attr(action), iframe::attr(src)').getall()
            for link in links:
                if link.startswith('javascript:'):
                    continue

                # [MỚI] Bắt các link nội bộ của SPA (dấu thăng)
                if link.startswith('#/'):
                    full_spa_url = response.urljoin(link)
                    yield {'url': full_spa_url}  # Trả về để ghi vào DB/Tree
                    continue  # Bỏ qua follow vì Scrapy (HTTP) không load được hash

                yield response.follow(link, self.parse, cookies=self.cookies_dict)

            # 2. Tìm file JS để phân tích tiếp
            js_files = response.css('script::attr(src)').getall()
            for js in js_files:
                yield response.follow(js, self.parse_js, cookies=self.cookies_dict)

    def parse_js(self, response):
        """Trích xuất API endpoints và SPA Routes ẩn trong file JavaScript"""
        yield {'url': response.url}

        body = response.text
        base_url = f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"

        # [CẬP NHẬT 1] Bắt các REST API ẩn (như cũ)
        api_endpoints = re.findall(r'["\'](/(?:api|rest|b2b|assets|ftp)/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)["\']',
                                   body)
        for ep in api_endpoints:
            yield {'url': f"{base_url}{ep}"}
            yield response.follow(ep, self.parse, cookies=self.cookies_dict)

        # [CẬP NHẬT 2] "Đọc trộm" cấu hình Route của Angular/React
        # Cấu trúc Angular thường là: path: "login", component: ...
        spa_routes = re.findall(r'path\s*:\s*[\'"]([a-zA-Z0-9_-]+)[\'"]', body)
        for route in spa_routes:
            if route not in ['**', '', '404']:
                spa_full_url = f"{base_url}/#/{route}"
                yield {'url': spa_full_url}  # Đẩy vào danh sách URL để xây Tree và quét DOM
