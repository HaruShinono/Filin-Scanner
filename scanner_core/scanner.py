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
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
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
    def __init__(self, url: str, cookies: Optional[str] = None, depth: int = 2, threads: int = 10,
                 pre_crawled_urls: set = None, discovered_forms: list = None):
        self.base_url = self._normalize_url(url)
        self.domain = urlparse(self.base_url).netloc
        self.depth = depth
        self.threads = threads
        self.session = self._create_session()

        if cookies:
            self._apply_cookies(cookies)

        self.visited_urls: Set[str] = pre_crawled_urls if pre_crawled_urls else set()
        if not self.visited_urls:
            self.visited_urls.add(self.base_url)

        self.discovered_forms = discovered_forms if discovered_forms else []
        self.lock = threading.Lock()
        self.payload_config = self._load_payload_config()
        self.testers = self._load_testers()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        spoofed_ip = f"{random.randint(11, 250)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept-Language': 'en-US,en;q=0.5',
            'X-Forwarded-For': spoofed_ip,
            'ngrok-skip-browser-warning': 'true'
        })
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
                            testers_list.append(obj(self.session, tester_config))
                except Exception:
                    pass
        return testers_list

    def _normalize_url(self, url: str) -> str:
        return url

    def scan(self, vulnerability_callback: Optional[Callable[[Vulnerability], None]] = None):
        print("\n" + "=" * 50, flush=True)
        print("🎯 TARGET ATTACK POINTS SECURED", flush=True)
        print("=" * 50, flush=True)
        for form in self.discovered_forms:
            params = [i['name'] for i in form.get('inputs', [])]
            print(f" [+] {form['method']} {form['url']} | Params: {params}", flush=True)
        print("=" * 50 + "\n", flush=True)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for tester in self.testers:
                tester_name = tester.__class__.__name__

                # 1. URL Injection
                for url in self.visited_urls:
                    futures[executor.submit(tester.test, url)] = (tester_name, url)

                # 2. Form/API Injection
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