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
        """Đồng bộ Cookies và LocalStorage Token cho trình duyệt Selenium"""
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
                # Đọc JWT Token nếu tồn tại
                if cookie.name.lower() in ['token', 'jwt', 'bearer'] or cookie.value.startswith('eyJ'):
                    token_value = cookie.value

            # Ghi đè Token vào LocalStorage để bypass cấu hình phân quyền Client-side của Angular [2]
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

        driver = None
        try:
            driver = self._get_selenium_driver()
            self._sync_session(driver, base_url)

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
        try:
            driver.get(url)
            time.sleep(3)

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
                pass

            alert = driver.switch_to.alert
            alert.accept()
            return True

        except (NoAlertPresentException, TimeoutException):
            return False
        except UnexpectedAlertPresentException:
            return True
        except Exception:
            return False