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
        self.payloads = self.config.get('payloads', [])

    def _get_selenium_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-xss-auditor")
        chrome_options.add_argument("--ignore-certificate-errors")

        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.managed_default_content_settings.stylesheets": 2,
            "profile.managed_default_content_settings.fonts": 2
        }
        chrome_options.add_experimental_option("prefs", prefs)

        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(15)
        return driver

    def _sync_session(self, driver, base_url):
        try:
            driver.get(f"{base_url}/favicon.ico")
            driver.add_cookie({'name': 'ngrok-skip-browser-warning', 'value': 'true', 'path': '/'})

            token_value = None
            for cookie in self.session.cookies:
                driver.add_cookie({
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain or urlparse(base_url).hostname,
                    'path': cookie.path or '/'
                })
                if cookie.name.lower() in ['token', 'jwt', 'bearer'] or cookie.value.startswith('eyJ'):
                    token_value = cookie.value

            if token_value:
                driver.execute_script(f"localStorage.setItem('token', '{token_value}');")
        except Exception:
            pass

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        has_query = bool(parsed.query)
        has_spa_query = bool(parsed.fragment and '?' in parsed.fragment)

        if not has_query and not has_spa_query:
            return vulns

        if any(parsed.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.pdf', '.js', '.svg']):
            return vulns

        print(f"  [DEBUG-DOMXSS] Analyzing Endpoint: {url}", flush=True)

        driver = None
        try:
            driver = self._get_selenium_driver()
            self._sync_session(driver, base_url)

            # --- 1. Test Query Parameters thường (VD: /search?q=1) ---
            if has_query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in self.payloads:
                        if not isinstance(payload, str): continue
                        test_params = params.copy()
                        test_params[param] = payload
                        new_query = urlencode(test_params, doseq=True)
                        target_url = urlunparse(parsed._replace(query=new_query))

                        print(f"  [DEBUG-DOMXSS] Fuzzing Query Param [{param}] -> {target_url[:80]}...", flush=True)
                        if self._check_alert(driver, target_url):
                            print(f"  [DEBUG-DOMXSS] !!! DOM XSS SUCCESS ON [{param}] !!!", flush=True)
                            vulns.append(Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='DOM-based XSS (Query)',
                                url=target_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Javascript Alert executed in the headless browser via location.search.'},
                                severity='High'
                            ))
                            break

            # --- 2. Test SPA Fragment Parameters (VD: /#/search?q=1) ---
            if has_spa_query:
                frag_path, frag_query = parsed.fragment.split('?', 1)
                frag_params = parse_qs(frag_query)

                for param in frag_params:
                    for payload in self.payloads:
                        if not isinstance(payload, str): continue
                        test_frag_params = frag_params.copy()
                        test_frag_params[param] = payload
                        new_frag_query = urlencode(test_frag_params, doseq=True)

                        new_fragment = f"{frag_path}?{new_frag_query}"
                        target_url = urlunparse(parsed._replace(fragment=new_fragment))

                        print(f"  [DEBUG-DOMXSS] Fuzzing SPA Param [{param}] -> {target_url[:80]}...", flush=True)
                        if self._check_alert(driver, target_url):
                            print(f"  [DEBUG-DOMXSS] !!! DOM XSS SUCCESS ON SPA [{param}] !!!", flush=True)
                            vulns.append(Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='DOM-based XSS (Fragment/Hash)',
                                url=target_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Javascript Alert executed via SPA Client-side Router (location.hash).'},
                                severity='High'
                            ))
                            break

        except Exception as e:
            print(f"  [DEBUG-DOMXSS] Error: {e}", flush=True)
        finally:
            if driver:
                driver.quit()

        return vulns

    def _check_alert(self, driver, url):
        """Mở URL và cố gắng ép Payload phát nổ"""
        try:
            # [QUAN TRỌNG] Ép trình duyệt mở trang trắng trước để xóa cache SPA Router
            driver.get("about:blank")
            # Sau đó mới mở URL có chứa payload
            driver.get(url)

            # Chờ Angular render DOM hoàn chỉnh
            time.sleep(3)

            # Bơm JS để Fuzz Event (ép các thẻ kích hoạt onmouseover, onfocus...)
            try:
                trigger_script = """
                var evts = ['mouseover', 'focus', 'click'];
                var inputs = document.querySelectorAll('input, button, a, div, iframe, svg');
                for(var i=0; i<Math.min(inputs.length, 50); i++) {
                    for(var e=0; e<evts.length; e++) {
                        try { inputs[i].dispatchEvent(new Event(evts[e])); } catch(err) {}
                    }
                }
                """
                driver.execute_script(trigger_script)
            except:
                pass

                # Kiểm tra xem có popup Alert bật lên không
            alert = driver.switch_to.alert
            alert.accept()
            return True

        except (NoAlertPresentException, TimeoutException):
            return False
        except UnexpectedAlertPresentException:
            # Lỗi này văng ra tức là Alert CÓ BẬT LÊN nhưng code Selenium bị gián đoạn vì nó.
            return True
        except Exception:
            return False