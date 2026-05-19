import scrapy
from urllib.parse import urlparse
import re


class SmartSpider(scrapy.Spider):
    name = 'smart_spider'

    def __init__(self, target='', depth_limit=2, auth_cookies='', *args, **kwargs):
        super(SmartSpider, self).__init__(*args, **kwargs)
        self.start_urls = [target]
        self.allowed_domains = [urlparse(target).netloc]

        # --- WAF EVASION & MODERN WEB SETTINGS ---
        self.custom_settings = {
            'DEPTH_LIMIT': int(depth_limit),
            'ROBOTSTXT_OBEY': False,  # Bỏ qua robots.txt để quét sâu hơn
            'LOG_LEVEL': 'ERROR',
            'CONCURRENT_REQUESTS': 8,  # Giữ mức vừa phải để không bị WAF ban
            'DOWNLOAD_DELAY': 0.5,  # Thêm delay nhẹ giữa các request
            'RANDOMIZE_DOWNLOAD_DELAY': True,
            'COOKIES_ENABLED': True,
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'DEFAULT_REQUEST_HEADERS': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        }

        # Parse cookies if provided
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

        # 1. Trích xuất link từ HTML (truyền thống)
        if 'text/html' in content_type:
            # Lấy thẻ a, form action, iframe src
            links = response.css('a::attr(href), form::attr(action), iframe::attr(src)').getall()
            for link in links:
                yield response.follow(link, self.parse, cookies=self.cookies_dict)

            # Tìm file JS để phân tích tiếp
            js_files = response.css('script::attr(src)').getall()
            for js in js_files:
                yield response.follow(js, self.parse_js, cookies=self.cookies_dict)

    def parse_js(self, response):
        """Trích xuất API endpoints hoặc routes ẩn trong file JavaScript (SPA Support)"""
        yield {'url': response.url}

        body = response.text
        # Regex tìm các chuỗi có dạng URL hoặc endpoint (bắt đầu bằng / hoặc http)
        # Giúp tìm ra các REST API được gọi ngầm trong JS
        endpoints = re.findall(r'["\'](/(?:api/|v1/|v2/)?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)["\']', body)

        for ep in endpoints:
            yield response.follow(ep, self.parse, cookies=self.cookies_dict)