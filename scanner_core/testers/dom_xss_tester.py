from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException
import time
import requests

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class DomXssTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        # Lấy payload từ config/payloads.yml (mục dom_xss)
        self.payloads = self.config.get('payloads', [])

    def _get_selenium_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")  # Engine headless mới của Chrome, nhanh và mượt hơn
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-xss-auditor")
        chrome_options.add_argument("--ignore-certificate-errors")

        # --- TỐI ƯU TỐC ĐỘ (MAXIMIZE PERFORMANCE) ---
        # Chặn tải hình ảnh, CSS, và font chữ vì chúng không cần thiết cho việc test XSS
        # Giúp tốc độ load trang của Selenium tăng gấp 3 lần
        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.managed_default_content_settings.stylesheets": 2,
            "profile.managed_default_content_settings.fonts": 2
        }
        chrome_options.add_experimental_option("prefs", prefs)

        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(10)  # Không đợi quá lâu cho 1 trang
        return driver

    def _sync_cookies(self, driver, base_url):
        """
        Đồng bộ Session Cookie (Authentication) và Bypass Ngrok cho Selenium.
        Selenium yêu cầu phải mở domain đó ra trước khi set cookie.
        """
        try:
            # Mở một trang trống trên cùng domain để được phép set cookie
            driver.get(f"{base_url}/favicon.ico")

            # Set cookie bypass Ngrok
            driver.add_cookie({'name': 'ngrok-skip-browser-warning', 'value': 'true', 'path': '/'})

            # Đồng bộ Cookie đăng nhập từ requests.Session
            for cookie in self.session.cookies:
                driver.add_cookie({
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain or urlparse(base_url).hostname,
                    'path': cookie.path or '/'
                })
        except Exception:
            pass

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Chỉ test nếu URL có tham số thường (?id=) HOẶC tham số SPA (#/search?q=)
        has_query = bool(parsed.query)
        has_spa_query = bool(parsed.fragment and '?' in parsed.fragment)

        if not has_query and not has_spa_query:
            return vulns

        # Bỏ qua file tĩnh
        if any(parsed.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.pdf', '.js', '.svg']):
            return vulns

        driver = None
        try:
            driver = self._get_selenium_driver()

            # Đồng bộ quyền truy cập (Auth + Ngrok) cho trình duyệt ảo
            self._sync_cookies(driver, base_url)

            # 1. Test Query Parameters thường (VD: /search?q=1)
            if has_query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in self.payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        new_query = urlencode(test_params, doseq=True)
                        target_url = urlunparse(parsed._replace(query=new_query))

                        if self._check_alert(driver, target_url):
                            vulns.append(Vulnerability(
                                type='DOM-based Cross-Site Scripting',
                                subcategory='Source: location.search',
                                url=target_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Javascript Alert executed in the headless browser.'},
                                severity='High'
                            ))
                            break

            # 2. Test SPA Fragment Parameters (VD: /#/search?q=1) -> ĐÂY LÀ CHỖ BẮT LỖI JUICE SHOP
            if has_spa_query:
                frag_path, frag_query = parsed.fragment.split('?', 1)
                frag_params = parse_qs(frag_query)

                for param in frag_params:
                    for payload in self.payloads:
                        test_frag_params = frag_params.copy()
                        test_frag_params[param] = payload
                        new_frag_query = urlencode(test_frag_params, doseq=True)

                        new_fragment = f"{frag_path}?{new_frag_query}"
                        target_url = urlunparse(parsed._replace(fragment=new_fragment))

                        if self._check_alert(driver, target_url):
                            vulns.append(Vulnerability(
                                type='DOM-based Cross-Site Scripting',
                                subcategory='Source: location.hash',
                                url=target_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Javascript Alert executed via SPA Client-side Router.'},
                                severity='High'
                            ))
                            break

        except Exception:
            pass
        finally:
            if driver:
                driver.quit()

        return vulns

    def _check_alert(self, driver, url):
        """Mở URL và cố gắng ép Payload phát nổ"""
        try:
            driver.get(url)

            # Chờ Angular/React render DOM hoàn chỉnh (Dynamic Rendering)
            time.sleep(1.5)

            # --- [MAXIMIZED] EVENT FUZZING ---
            # Nhiều payload (như onmouseover, onfocus) cần tương tác người dùng mới chạy.
            # Ta dùng Javascript bơm vào trang để giả lập việc trỏ chuột và click mọi nơi.
            try:
                trigger_script = """
                var evts = ['mouseover', 'focus', 'click'];
                var inputs = document.querySelectorAll('input, button, a, div');
                for(var i=0; i<Math.min(inputs.length, 50); i++) {
                    for(var e=0; e<evts.length; e++) {
                        try { inputs[i].dispatchEvent(new Event(evts[e])); } catch(err) {}
                    }
                }
                """
                driver.execute_script(trigger_script)
            except:
                pass  # Bỏ qua nếu JS trigger bị lỗi

            # Kiểm tra xem có popup Alert bật lên không
            alert = driver.switch_to.alert
            alert.accept()
            return True

        except (NoAlertPresentException, TimeoutException):
            return False
        except UnexpectedAlertPresentException:
            # Lỗi này văng ra tức là Alert CÓ BẬT LÊN nhưng code Selenium bị gián đoạn vì nó.
            # Đây là dấu hiệu chắc chắn 100% của XSS.
            return True
        except Exception:
            return False