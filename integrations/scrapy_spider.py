# integrations/scrapy_spider.py
import scrapy
from urllib.parse import urlparse


class SiteSpider(scrapy.Spider):
    name = 'site_spider'

    def __init__(self, target='', depth_limit=2, *args, **kwargs):
        super(SiteSpider, self).__init__(*args, **kwargs)
        self.start_urls = [target]
        self.allowed_domains = [urlparse(target).netloc]

        self.custom_settings = {
            'DEPTH_LIMIT': int(depth_limit),
            'ROBOTSTXT_OBEY': False,
            'LOG_LEVEL': 'ERROR',  # Tắt log rác của Scrapy
            'CONCURRENT_REQUESTS': 16,  # Tăng tốc độ thu thập
            'DOWNLOAD_TIMEOUT': 10
        }

    def parse(self, response):
        # Trả về URL hợp lệ
        yield {'url': response.url}

        # Bắt tất cả các link trên trang để đi tiếp
        if 'text/html' in response.headers.get('Content-Type', b'').decode('utf-8').lower():
            for href in response.css('a::attr(href)').getall():
                yield response.follow(href, self.parse)