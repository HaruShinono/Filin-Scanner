import importlib
import inspect
import logging
import os
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
import yaml
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
]


@dataclass
class Vulnerability:
    type: str
    url: str
    details: Dict
    severity: str
    subcategory: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None


class Scanner:
    # [MỚI] Thêm tham số waf_detected
    def __init__(self, url: str, cookies: Optional[str] = None, depth: int = 2, threads: int = 10,
                 pre_crawled_urls: set = None, discovered_forms: list = None, waf_detected: bool = False, is_windows: bool = False):
        self.base_url = self._normalize_url(url)
        self.domain = urlparse(self.base_url).netloc
        self.depth = depth
        self.threads = threads
        self.waf_detected = waf_detected  # Lưu cờ WAF
        self.session = self._create_session()

        if cookies:
            self._apply_cookies(cookies)

        self.visited_urls: Set[str] = pre_crawled_urls if pre_crawled_urls else set()
        if not self.visited_urls:
            self.visited_urls.add(self.base_url)

        self.discovered_forms = discovered_forms if discovered_forms else []

        self.lock = threading.Lock()

        self.payload_config = self._load_payload_config()
        self.payload_config['is_windows'] = self.is_windows
        self.testers = self._load_testers()
        logger.info(f"Loaded {len(self.testers)} tester modules.")

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Headers cơ bản luôn có mặt (Bao gồm bypass Ngrok)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'ngrok-skip-browser-warning': 'true'
        }

        # [MỚI] NẾU CÓ WAF: Bật Evasion Techniques
        if self.waf_detected:
            spoofed_ip = f"{random.randint(11, 250)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            headers['X-Forwarded-For'] = spoofed_ip
            headers['X-Real-IP'] = spoofed_ip
            headers['Client-IP'] = spoofed_ip
            headers['User-Agent'] = random.choice(USER_AGENTS)
            logger.info("WAF detected. Enabled IP Spoofing and User-Agent rotation.")
        else:
            headers['User-Agent'] = USER_AGENTS[0]  # Dùng UA chuẩn nếu không có WAF

        session.headers.update(headers)
        session.verify = False
        return session

    def _apply_cookies(self, cookie_string: str):
        try:
            cookie_dict = {}
            for item in cookie_string.split(';'):
                if '=' in item:
                    name, value = item.strip().split('=', 1)
                    cookie_dict[name] = value
                    if name.lower() in ['token', 'jwt', 'bearer'] or value.startswith('eyJ'):
                        self.session.headers.update({'Authorization': f'Bearer {value}'})
            self.session.cookies.update(cookie_dict)
        except Exception:
            pass

    def _load_payload_config(self) -> dict:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'payloads.yml')
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception:
            return {}

    def _load_testers(self) -> List:
        testers_list = []
        testers_path = os.path.join(os.path.dirname(__file__), 'testers')
        from .testers.base_tester import BaseTester
        for filename in os.listdir(testers_path):
            if filename.endswith('_tester.py') and filename != 'base_tester.py':
                module_name = f"scanner_core.testers.{filename[:-3]}"
                config_key = filename.replace('_tester.py', '')
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BaseTester) and obj is not BaseTester:
                            tester_config = self.payload_config.get(config_key, {})
                            tester_config['is_windows'] = self.is_windows
                            testers_list.append(obj(self.session, tester_config))
                except Exception:
                    pass
        return testers_list

    def _normalize_url(self, url: str) -> str:
        return url

    def scan(self, vulnerability_callback: Optional[Callable[[Vulnerability], None]] = None):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for tester in self.testers:
                tester_name = tester.__class__.__name__

                for url in self.visited_urls:
                    futures[executor.submit(tester.test, url)] = (tester_name, url)

                if hasattr(tester, 'test_form'):
                    for form in self.discovered_forms:
                        futures[executor.submit(tester.test_form, form)] = (tester_name,
                                                                            f"{form['url']} [{form['method']}]")

            for future in as_completed(futures):
                tester_name, url_tested = futures[future]
                try:
                    results = future.result()
                    if not results: continue
                    if not isinstance(results, list): results = [results]

                    for vuln in results:
                        if isinstance(vuln, Vulnerability):
                            if vulnerability_callback:
                                vulnerability_callback(vuln)
                except Exception:
                    pass