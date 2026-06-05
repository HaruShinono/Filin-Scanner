from typing import List, Optional
import urllib.parse  # Sửa lỗi import để dùng quote
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait  # Bổ sung Explicit Wait
from selenium.webdriver.support import expected_conditions as EC  # Bổ sung Conditions
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
                    'domain': cookie.domain or urllib.parse.urlparse(base_url).hostname,
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
        parsed = urllib.parse.urlparse(url)
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
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    for payload in self.payloads:
                        if not isinstance(payload, str): continue
                        test_params = params.copy()
                        test_params[param] = payload

                        # [FIX LỖI URL ENCODING] Sử dụng quote thay vì quote_plus để khoảng trắng ra %20
                        new_query = urllib.parse.urlencode(test_params, doseq=True, quote_via=urllib.parse.quote)
                        target_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                        print(f"  [DEBUG-DOMXSS] Fuzzing Query Param [{param}] -> {target_url[:100]}...", flush=True)
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
                frag_params = urllib.parse.parse_qs(frag_query)

                for param in frag_params:
                    for payload in self.payloads:
                        if not isinstance(payload, str): continue
                        test_frag_params = frag_params.copy()
                        test_frag_params[param] = payload

                        # blank -> %20
                        new_frag_query = urllib.parse.urlencode(test_frag_params, doseq=True,
                                                                quote_via=urllib.parse.quote)

                        new_fragment = f"{frag_path}?{new_frag_query}"
                        target_url = urllib.parse.urlunparse(parsed._replace(fragment=new_fragment))
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
        try:
            driver.get("about:blank")

            try:
                driver.get(url)
            except UnexpectedAlertPresentException:
                return True

            try:
                WebDriverWait(driver, 4).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert.accept()
                return True
            except TimeoutException:
                pass
            except UnexpectedAlertPresentException:
                return True
            try:
                trigger_script = """
                var evts = ['mouseover', 'focus', 'click', 'mouseenter', 'mouseleave'];
                var inputs = document.querySelectorAll('input, button, a, div, iframe, svg, img, details');
                for(var i=0; i<Math.min(inputs.length, 50); i++) {
                    for(var e=0; e<evts.length; e++) {
                        try { inputs[i].dispatchEvent(new Event(evts[e])); } catch(err) {}
                    }
                }
                """
                driver.execute_script(trigger_script)

                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert.accept()
                return True
            except TimeoutException:
                pass
            except UnexpectedAlertPresentException:
                return True
            except Exception:
                pass

        except UnexpectedAlertPresentException:
            # Bắt chót mọi trường hợp Alert ngoại lệ
            return True
        except Exception:
            pass

        return False