import json
import logging
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)


class PlaywrightCrawler:
    def __init__(self, target_url, auth_cookies=None, scan_mode='full'):
        self.target_url = target_url
        self.auth_cookies = auth_cookies
        self.scan_mode = scan_mode
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.discovered_apis = []
        self.seen_signatures = set()  # Tránh lưu trùng lặp API

    def _handle_request(self, request):
        """Hàm này tự động kích hoạt mỗi khi trang web gửi đi bất kỳ request nào"""
        url = request.url
        method = request.method

        # Bỏ qua các request lấy file tĩnh
        if any(url.lower().endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.woff2', '.ico']):
            return

        # Chỉ bắt các API gửi đi từ cùng một domain
        if self.base_url in url and method in ['POST', 'PUT', 'PATCH', 'DELETE', 'GET']:
            inputs = []
            is_api = False

            # Xử lý POST/PUT body
            post_data = request.post_data
            if post_data:
                try:
                    # Parse JSON Body
                    json_data = json.loads(post_data)
                    is_api = True
                    if isinstance(json_data, dict):
                        for k, v in json_data.items():
                            inputs.append({'name': k, 'value': str(v), 'type': 'text'})
                except:
                    # Parse Form Data
                    for pair in post_data.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            inputs.append({'name': k, 'value': v, 'type': 'text'})

            # Xử lý GET parameters
            if method == 'GET' and '?' in url:
                from urllib.parse import parse_qsl
                query = url.split('?')[1]
                for k, v in parse_qsl(query):
                    inputs.append({'name': k, 'value': v, 'type': 'text'})

            # Nếu có data/param, lưu lại thành Form
            if inputs or method != 'GET':  # POST không cần input vẫn tính là 1 endpoint
                api_finding = {
                    'type': 'form',
                    'url': url.split('?')[0],  # Chỉ lấy đường dẫn gốc
                    'method': method,
                    'inputs': inputs,
                    'is_api': is_api or 'application/json' in request.headers.get('content-type', '').lower()
                }

                # Tạo signature để tránh lưu trùng lặp (ví dụ 1 API gọi 10 lần)
                sig = f"{method}:{api_finding['url']}"
                if sig not in self.seen_signatures:
                    self.seen_signatures.add(sig)
                    self.discovered_apis.append(api_finding)

    def crawl(self):
        print(f"  [Playwright Crawler] Launching modern headless browser on {self.target_url}...")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            # Setup Cookies & Ngrok Bypass
            context.add_cookies([{'name': 'ngrok-skip-browser-warning', 'value': 'true', 'url': self.base_url}])
            if self.auth_cookies:
                for item in self.auth_cookies.split(';'):
                    if '=' in item:
                        k, v = item.strip().split('=', 1)
                        context.add_cookies([{'name': k, 'value': v, 'url': self.base_url}])

            page = context.new_page()

            # Đăng ký hàm lắng nghe request
            page.on("request", self._handle_request)

            try:
                if self.scan_mode == 'single':
                    test_routes = [self.target_url]
                else:
                    # Mở rộng các route thường gặp của SPA
                    test_routes = [
                        f"{self.base_url}/", f"{self.base_url}/#/login", f"{self.base_url}/#/register",
                        f"{self.base_url}/#/search", f"{self.base_url}/#/contact", f"{self.base_url}/#/basket",
                        f"{self.base_url}/#/profile"
                    ]

                for url in test_routes:
                    try:
                        page.goto(url, wait_until="networkidle", timeout=10000)

                        # --- HACK CỰC MẠNH: Tương tác với DOM ---
                        # 1. Điền dữ liệu vào MỌI ô input nó thấy
                        page.evaluate("""
                            document.querySelectorAll('input').forEach(i => {
                                i.value = 'test_payload@juice-sh.op';
                                i.dispatchEvent(new Event('input', { bubbles: true }));
                                i.dispatchEvent(new Event('change', { bubbles: true }));
                            });
                        """)

                        # 2. Bấm phím Enter trên các ô search
                        page.keyboard.press("Enter")

                        # 3. Click vào MỌI nút bấm trên màn hình
                        # Hành động này sẽ trigger Angular bắn API đi, Playwright sẽ tóm sống nó!
                        page.evaluate("""
                            document.querySelectorAll('button:not([disabled])').forEach(b => b.click());
                        """)

                        page.wait_for_timeout(1000)  # Đợi API bay đi
                    except Exception as e:
                        pass  # Bỏ qua lỗi timeout của từng trang con

            except Exception as e:
                logger.error(f"Playwright error: {e}")
            finally:
                browser.close()

        print(f"  [Playwright Crawler] Captured {len(self.discovered_apis)} APIs/Forms via Deep Interception!")
        return self.discovered_apis