import json
import logging
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright
import time

logger = logging.getLogger(__name__)


class PlaywrightCrawler:
    def __init__(self, target_url, auth_cookies=None, scan_mode='full'):
        self.target_url = target_url
        self.auth_cookies = auth_cookies
        self.scan_mode = scan_mode
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.discovered_apis = []
        self.seen_signatures = set()

    def _handle_request(self, request):
        url = request.url
        method = request.method

        if any(url.lower().endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.woff2', '.ico']):
            return

        if self.base_url in url and method in ['POST', 'PUT', 'PATCH', 'DELETE', 'GET']:
            inputs = []
            is_api = False

            raw_headers = request.headers
            captured_headers = {}
            for k, v in raw_headers.items():
                if k.lower() in ['authorization', 'content-type', 'accept', 'x-csrf-token']:
                    captured_headers[k] = v

            post_data = request.post_data
            if post_data:
                try:
                    json_data = json.loads(post_data)
                    is_api = True
                    if isinstance(json_data, dict):
                        for k, v in json_data.items():
                            inputs.append({'name': k, 'value': str(v), 'type': 'text'})
                except:
                    for pair in post_data.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            inputs.append({'name': k, 'value': v, 'type': 'text'})

            if method == 'GET' and '?' in url:
                from urllib.parse import parse_qsl
                query = url.split('?')[1]
                for k, v in parse_qsl(query):
                    inputs.append({'name': k, 'value': v, 'type': 'text'})

            if inputs or method != 'GET':
                api_finding = {
                    'type': 'form',
                    'url': url.split('?')[0],
                    'method': method,
                    'inputs': inputs,
                    'is_api': is_api or 'application/json' in request.headers.get('content-type', '').lower(),
                    'headers': captured_headers
                }

                sig = f"{method}:{api_finding['url']}"
                if sig not in self.seen_signatures:
                    self.seen_signatures.add(sig)
                    self.discovered_apis.append(api_finding)
                    print(f"  [DEBUG-PLAYWRIGHT] Captured API: {method} {api_finding['url']}", flush=True)

    def crawl(self):
        print(f"  [Playwright Crawler] Launching modern headless browser on {self.target_url}...", flush=True)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            context.add_cookies([{'name': 'ngrok-skip-browser-warning', 'value': 'true', 'url': self.base_url}])

            token_value = None
            if self.auth_cookies:
                for item in self.auth_cookies.split(';'):
                    if '=' in item:
                        k, v = item.strip().split('=', 1)
                        context.add_cookies([{'name': k, 'value': v, 'url': self.base_url}])
                        if k.lower() in ['token', 'jwt', 'bearer'] or v.startswith('eyJ'):
                            token_value = v

            page = context.new_page()
            page.on("request", self._handle_request)

            try:
                page.goto(self.base_url, wait_until="domcontentloaded", timeout=10000)
                page.wait_for_timeout(2000)

                if token_value:
                    page.evaluate(f"localStorage.setItem('token', '{token_value}')")
                    print("  [DEBUG-PLAYWRIGHT] Token injected into LocalStorage", flush=True)

                if self.scan_mode == 'single':
                    test_routes = [self.target_url]
                else:
                    test_routes = [
                        f"{self.base_url}/",
                        f"{self.base_url}/#/login",
                        f"{self.base_url}/#/register",
                        f"{self.base_url}/#/search",
                        f"{self.base_url}/#/contact",
                        f"{self.base_url}/#/forgot-password",
                        f"{self.base_url}/#/basket"
                    ]

                for url in test_routes:
                    try:
                        print(f"  [DEBUG-PLAYWRIGHT] Navigating to: {url}", flush=True)
                        page.goto(url, wait_until="domcontentloaded", timeout=10000)
                        page.wait_for_timeout(2000)

                        page.evaluate("""
                            const dismissBtn = Array.from(document.querySelectorAll('button')).find(el => el.textContent.includes('Dismiss'));
                            if (dismissBtn) { dismissBtn.click(); }

                            const cookieBtn = Array.from(document.querySelectorAll('a')).find(el => el.getAttribute('aria-label') === 'dismiss cookie message');
                            if (cookieBtn) { cookieBtn.click(); }
                        """)
                        page.wait_for_timeout(500)

                        inputs = page.query_selector_all('input')
                        print(f"  [DEBUG-PLAYWRIGHT] Found {len(inputs)} input fields on page", flush=True)

                        for inp in inputs:
                            try:
                                inp_type = inp.get_attribute('type') or 'text'
                                inp_id = inp.get_attribute('id') or ''
                                inp_name = inp.get_attribute('name') or ''
                                placeholder = inp.get_attribute('placeholder') or ''

                                if 'email' in inp_id.lower() or 'email' in inp_name.lower():
                                    inp.focus()
                                    inp.fill('admin@juice-sh.op')
                                    print(f"  [DEBUG-PLAYWRIGHT] Filled email field", flush=True)
                                elif inp_type == 'password':
                                    inp.focus()
                                    inp.fill('admin123')
                                    print(f"  [DEBUG-PLAYWRIGHT] Filled password field", flush=True)
                                elif 'search' in inp_id.lower() or 'search' in inp_name.lower() or 'search' in placeholder.lower():
                                    inp.focus()
                                    inp.fill('apple')
                                    page.keyboard.press("Enter")
                                    print(f"  [DEBUG-PLAYWRIGHT] Performed search query", flush=True)
                                else:
                                    inp.focus()
                                    inp.fill('test_fuzzing_data')
                            except Exception:
                                pass

                        search_icon = page.query_selector('.mat-search-button, #searchQuery')
                        if search_icon:
                            try:
                                search_icon.click()
                                page.keyboard.type('apple')
                                page.keyboard.press("Enter")
                                print(f"  [DEBUG-PLAYWRIGHT] Clicked search icon and submitted query", flush=True)
                            except:
                                pass

                        buttons = page.query_selector_all('button:not([disabled])')
                        for btn in buttons:
                            try:
                                btn_text = btn.inner_text().lower()
                                if any(k in btn_text for k in
                                       ['log in', 'login', 'submit', 'register', 'search', 'send']):
                                    print(f"  [DEBUG-PLAYWRIGHT] Clicking action button: '{btn.inner_text()}'",
                                          flush=True)
                                    btn.click()
                                    page.wait_for_timeout(500)
                            except:
                                pass

                        page.wait_for_timeout(1500)
                    except Exception as e:
                        print(f"  [DEBUG-PLAYWRIGHT] Failed to interact with {url}: {e}", flush=True)

            except Exception as e:
                print(f"  [DEBUG-PLAYWRIGHT] Main route error: {e}", flush=True)
            finally:
                browser.close()

        print(f"  [Playwright Crawler] Captured {len(self.discovered_apis)} API Endpoints/Forms via Deep Interception!",
              flush=True)
        return self.discovered_apis