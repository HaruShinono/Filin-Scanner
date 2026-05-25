import time
import json
import logging
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class DynamicCrawler:
    def __init__(self, target_url, auth_cookies=None):
        self.target_url = target_url
        self.auth_cookies = auth_cookies
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.discovered_apis = []

    def _get_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")

        # [QUAN TRỌNG NHẤT] Bật tính năng ghi log hiệu năng (Network Interception)
        chrome_options.set_capability(
            "goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"}
        )
        return webdriver.Chrome(options=chrome_options)

    def crawl(self):
        print(f"  [Dynamic Crawler] Launching Headless Browser on {self.target_url}...")
        driver = self._get_driver()

        try:
            # 1. Truy cập trang chủ & Bypass Ngrok
            driver.get(f"{self.base_url}/favicon.ico")
            driver.add_cookie({'name': 'ngrok-skip-browser-warning', 'value': 'true', 'path': '/'})

            # Cắm auth cookies nếu có
            if self.auth_cookies:
                for item in self.auth_cookies.split(';'):
                    if '=' in item:
                        k, v = item.strip().split('=', 1)
                        driver.add_cookie({'name': k, 'value': v, 'path': '/'})

            # 2. Bắt đầu thu thập các trang quan trọng của SPA
            # Dành riêng cho cấu trúc phổ biến của SPA / Juice Shop
            test_routes = ['/', '/#/login', '/#/search', '/#/contact', '/#/basket']

            for route in test_routes:
                full_url = f"{self.base_url}{route}"
                driver.get(full_url)
                time.sleep(2)  # Chờ Angular render DOM

                # --- FUZZING GIAO DIỆN (BẤM NÚT ĐỂ KÍCH HOẠT API) ---
                # Điền bừa vào các ô input và bấm nút submit để xem Angular bắn API gì
                try:
                    script = """
                    document.querySelectorAll('input').forEach(i => i.value = 'admin@juice-sh.op');
                    document.querySelectorAll('button').forEach(b => b.click());
                    """
                    driver.execute_script(script)
                    time.sleep(1)  # Chờ API bay đi
                except:
                    pass

            # 3. "NGHE LÉN" MẠNG (Đọc Network Logs)
            logs = driver.get_log("performance")

            for entry in logs:
                log = json.loads(entry["message"])["message"]

                # Bắt các request chuẩn bị được gửi đi (XHR/Fetch)
                if log["method"] == "Network.requestWillBeSent":
                    request_data = log["params"]["request"]
                    req_url = request_data["url"]
                    req_method = request_data["method"]

                    # Chỉ lọc các API nội bộ, bỏ qua file tĩnh (.js, .css, ảnh...)
                    if self.base_url in req_url and not any(
                            req_url.lower().endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.ico', '.woff2']):

                        # Parse Post Data (Body của API)
                        post_data = request_data.get("postData", "")
                        inputs = []

                        if post_data:
                            try:
                                # Nếu là JSON API (Giống Login của Juice Shop)
                                json_data = json.loads(post_data)
                                for k, v in json_data.items():
                                    inputs.append({'name': k, 'value': v, 'type': 'text'})
                            except:
                                # Nếu là Form-data
                                for pair in post_data.split('&'):
                                    if '=' in pair:
                                        k, v = pair.split('=', 1)
                                        inputs.append({'name': k, 'value': v, 'type': 'text'})

                        # Lưu API tìm được
                        api_finding = {
                            'type': 'form',  # Fake type form để Core Scanner hiểu
                            'url': req_url,
                            'method': req_method,
                            'inputs': inputs,
                            'is_api': 'application/json' in request_data.get('headers', {}).get('Content-Type',
                                                                                                '').lower() or '{' in post_data
                        }

                        # Tránh lưu trùng lặp
                        if api_finding not in self.discovered_apis and req_method in ['POST', 'PUT', 'DELETE', 'GET']:
                            self.discovered_apis.append(api_finding)

            print(
                f"  [Dynamic Crawler] Captured {len(self.discovered_apis)} hidden API Endpoints/Forms via Network Interception!")

        except Exception as e:
            logger.error(f"Dynamic Crawler error: {e}")
        finally:
            driver.quit()

        return self.discovered_apis