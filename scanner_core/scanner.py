import importlib
import inspect
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
import yaml
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    type: str
    url: str
    details: Dict
    severity: str
    subcategory: Optional[str] = None


class Scanner:
    def __init__(self, url: str, cookies: Optional[str] = None, depth: int = 2, threads: int = 10):
        self.base_url = self._normalize_url(url)
        self.domain = urlparse(self.base_url).netloc
        self.depth = depth
        self.threads = threads

        self.session = self._create_session()

        if cookies:
            self._apply_cookies(cookies)

        self.visited_urls: Set[str] = set()
        self.lock = threading.Lock()

        self.payload_config = self._load_payload_config()
        self.testers = self._load_testers()
        logger.info(f"Loaded {len(self.testers)} tester modules.")

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
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

            self.session.cookies.update(cookie_dict)
            logger.info(f"Authenticated Scan enabled. Cookies applied: {list(cookie_dict.keys())}")
        except Exception as e:
            logger.error(f"Failed to parse cookies: {e}")

    def _load_payload_config(self) -> dict:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'payloads.yml')
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Payload config file not found at: {config_path}")
            return {}
        except Exception as e:
            logger.error(f"Error loading payload config: {e}")
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
                            logger.debug(f"Successfully loaded tester: {name} with config for '{config_key}'")
                except Exception as e:
                    logger.error(f"Failed to load tester from {module_name}: {e}")
        return testers_list

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))

    def _is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return False

        if parsed.netloc != self.domain:
            return False

        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.ttf', '.eot',
                             '.pdf', '.zip', '.mp4']
        if any(parsed.path.lower().endswith(ext) for ext in static_extensions):
            return False

        return True

    def crawl(self, url: str, current_depth: int):
        if current_depth > self.depth:
            return

        normalized_url = self._normalize_url(url)
        with self.lock:
            if normalized_url in self.visited_urls:
                return
            self.visited_urls.add(normalized_url)

        logger.info(f"Crawling [Depth {current_depth}]: {normalized_url}")

        try:
            response = self.session.get(normalized_url, timeout=10)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_link = urljoin(self.base_url, link['href'])
                if self._is_valid_url(absolute_link):
                    self.crawl(absolute_link, current_depth + 1)
        except requests.RequestException as e:
            logger.warning(f"Crawl error for {normalized_url}: {e}")

    def scan(self, vulnerability_callback: Optional[Callable[[Vulnerability], None]] = None):
        logger.info(f"--- Starting Scan on {self.base_url} ---")
        logger.info("Phase 1: Crawling for URLs...")
        self.crawl(self.base_url, 0)
        logger.info(f"Crawling complete. Found {len(self.visited_urls)} unique URLs.")

        logger.info(f"Phase 2: Running {len(self.testers)} types of tests on all URLs...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(tester.test, url): (tester.__class__.__name__, url)
                for tester in self.testers
                for url in self.visited_urls
            }

            total_tasks = len(futures)
            completed_tasks = 0

            for future in as_completed(futures):
                tester_name, url_tested = futures[future]
                completed_tasks += 1
                logger.info(f"Progress: {completed_tasks}/{total_tasks} ({completed_tasks / total_tasks:.1%})")

                try:
                    results = future.result()
                    if not results:
                        continue

                    if not isinstance(results, list):
                        results = [results]

                    for vuln in results:
                        if isinstance(vuln, Vulnerability):
                            logger.warning(
                                f"VULNERABILITY FOUND by {tester_name} on {url_tested}: {vuln.type} ({vuln.severity})")
                            if vulnerability_callback and callable(vulnerability_callback):
                                vulnerability_callback(vuln)
                except Exception as e:
                    logger.error(f"Error running tester '{tester_name}' on {url_tested}: {e}")

        logger.info("--- Scan Finished ---")