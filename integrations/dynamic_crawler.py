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

            if self.scan_mode == 'single':
                test_routes = [self.target_url]
            else:
                test_routes = [
                    f"{self.base_url}/",
                    f"{self.base_url}/#/login",
                    f"{self.base_url}/#/search",
                    f"{self.base_url}/#/contact",
                    f"{self.base_url}/#/register"
                ]

            for full_url in test_routes:
                try:
                    driver.get(full_url)
                    time.sleep(2)  # Chờ load UI

                    # --- [NÂNG CẤP] SMART FUZZING SCRIPT ---
                    script = """
                    // 1. Tắt các popup che màn hình (Welcome, Cookies của Juice Shop)
                    document.querySelectorAll('.cc-dismiss, .close-dialog').forEach(b => b.click());

                    // Hàm giả lập gõ phím để đánh lừa Angular/React
                    function fillInput(input, value) {
                        input.value = value;
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                    }

                    // 2. Tương tác với tất cả ô nhập liệu
                    document.querySelectorAll('input').forEach(input => {
                        let type = input.getAttribute('type') || 'text';
                        let name = input.getAttribute('name') || input.getAttribute('id') || '';

                        // Điền form Login/Register
                        if (name.toLowerCase().includes('email')) {
                            fillInput(input, 'admin@juice-sh.op');
                        } else if (type === 'password') {
                            fillInput(input, 'admin123');
                        } 
                        // Điền các form text khác và giả lập bấm Enter (cho form search)
                        else if (type === 'text' || type === 'search') {
                            fillInput(input, 'apple');
                            input.dispatchEvent(new KeyboardEvent('keyup', {'key': 'Enter', 'bubbles': true}));
                        }
                    });

                    // 3. Bấm tất cả các nút KHÔNG BỊ KHÓA
                    setTimeout(() => {
                        document.querySelectorAll('button:not([disabled])').forEach(b => b.click());
                    }, 500);
                    """
                    driver.execute_script(script)
                    time.sleep(2)  # Chờ API bắn đi sau khi click
                    # ----------------------------------------
                except Exception as e:
                    pass

            # ĐỌC NETWORK LOG
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

                        # Nếu là POST/PUT, lấy dữ liệu payload
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

                        # Nếu là GET mà có params trên URL (như Search), bóc tách params ra
                        elif req_method == 'GET' and '?' in req_url:
                            from urllib.parse import parse_qsl
                            query = req_url.split('?')[1]
                            for k, v in parse_qsl(query):
                                inputs.append({'name': k, 'value': v, 'type': 'text'})

                        api_finding = {
                            'type': 'form',
                            'url': req_url.split('?')[0],  # Chỉ lấy base API path
                            'method': req_method,
                            'inputs': inputs,
                            'is_api': 'application/json' in request_data.get('headers', {}).get('Content-Type',
                                                                                                '').lower() or '{' in post_data
                        }

                        if req_method in ['POST', 'PUT', 'DELETE', 'PATCH',
                                          'GET'] and inputs and api_finding not in self.discovered_apis:
                            self.discovered_apis.append(api_finding)

            print(
                f"  [Dynamic Crawler] Captured {len(self.discovered_apis)} hidden API Endpoints/Forms via Network Interception!")

        except Exception as e:
            logger.error(f"Dynamic Crawler error: {e}")
        finally:
            driver.quit()

        return self.discovered_apis