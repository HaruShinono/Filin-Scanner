import time
import json
import logging
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class DynamicCrawler:
    def __init__(self, target_url, auth_cookies=None, scan_mode='full'):
        self.target_url = target_url
        self.auth_cookies = auth_cookies
        self.scan_mode = scan_mode
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.discovered_apis = []

    def _get_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")

        chrome_options.set_capability(
            "goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"}
        )
        return webdriver.Chrome(options=chrome_options)

    def crawl(self):
        print(f"  [Dynamic Crawler] Launching Headless Browser on {self.target_url}...")
        driver = self._get_driver()

        try:
            driver.get(f"{self.base_url}/favicon.ico")
            driver.add_cookie({'name': 'ngrok-skip-browser-warning', 'value': 'true', 'path': '/'})

            if self.auth_cookies:
                for item in self.auth_cookies.split(';'):
                    if '=' in item:
                        k, v = item.strip().split('=', 1)
                        driver.add_cookie({'name': k, 'value': v, 'path': '/'})

            # Xác định danh sách URL cần giả lập thao tác người dùng
            if self.scan_mode == 'single':
                test_routes = [self.target_url]
            else:
                test_routes = [
                    f"{self.base_url}/",
                    f"{self.base_url}/#/login",
                    f"{self.base_url}/#/search",
                    f"{self.base_url}/#/contact",
                    f"{self.base_url}/#/basket"
                ]

            for full_url in test_routes:
                try:
                    driver.get(full_url)
                    time.sleep(2)

                    script = """
                    document.querySelectorAll('input').forEach(i => i.value = 'admin@juice-sh.op');
                    document.querySelectorAll('button').forEach(b => b.click());
                    """
                    driver.execute_script(script)
                    time.sleep(1)
                except:
                    pass

            logs = driver.get_log("performance")

            for entry in logs:
                log = json.loads(entry["message"])["message"]

                if log["method"] == "Network.requestWillBeSent":
                    request_data = log["params"]["request"]
                    req_url = request_data["url"]
                    req_method = request_data["method"]

                    if self.base_url in req_url and not any(req_url.lower().endswith(ext) for ext in
                                                            ['.js', '.css', '.png', '.jpg', '.ico', '.woff2', '.svg']):
                        post_data = request_data.get("postData", "")
                        inputs = []

                        if post_data:
                            try:
                                json_data = json.loads(post_data)
                                if isinstance(json_data, dict):
                                    for k, v in json_data.items():
                                        inputs.append({'name': k, 'value': str(v), 'type': 'text'})
                            except:
                                for pair in post_data.split('&'):
                                    if '=' in pair:
                                        k, v = pair.split('=', 1)
                                        inputs.append({'name': k, 'value': v, 'type': 'text'})

                        api_finding = {
                            'type': 'form',
                            'url': req_url,
                            'method': req_method,
                            'inputs': inputs,
                            'is_api': 'application/json' in request_data.get('headers', {}).get('Content-Type',
                                                                                                '').lower() or '{' in post_data
                        }

                        if req_method in ['POST', 'PUT', 'DELETE', 'PATCH'] and api_finding not in self.discovered_apis:
                            self.discovered_apis.append(api_finding)

            print(
                f"  [Dynamic Crawler] Captured {len(self.discovered_apis)} hidden API Endpoints/Forms via Network Interception!")

        except Exception as e:
            pass
        finally:
            driver.quit()

        return self.discovered_apis