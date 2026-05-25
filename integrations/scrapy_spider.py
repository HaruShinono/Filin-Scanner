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
        # Lưu URL hiện tại
        yield {'url': response.url}

        content_type = response.headers.get('Content-Type', b'').decode('utf-8').lower()

        # NẾU LÀ HTML: Thu thập links và tìm file JS
        if 'text/html' in content_type:
            # Thu thập thẻ <a>, <form> (Truyền thống)
            links = response.css('a::attr(href), form::attr(action)').getall()
            for link in links:
                if not link.startswith(('#', 'javascript:')):
                    yield response.follow(link, self.parse, cookies=self.cookies_dict)


            js_files = response.css('script::attr(src)').getall()
            for js in js_files:
                yield response.follow(js, self.parse_js, cookies=self.cookies_dict)

    def parse_js(self, response):
        yield {'url': response.url}

        body = response.text

        # Regex tìm các REST API phổ biến (phù hợp với cấu trúc Juice Shop)
        # Bắt các chuỗi như: "/api/Users", "/rest/products/search", "/api/Feedbacks"
        api_endpoints = re.findall(r'["\'](/(?:api|rest|v1|v2)/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)["\']', body)

        for ep in api_endpoints:
            # Gửi request tới API endpoint tìm được
            yield response.follow(ep, self.parse, cookies=self.cookies_dict)