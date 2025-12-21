# scanner_core/testers/dom_xss_tester.py
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException
import time

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class DomXssTester(BaseTester):
    def __init__(self, session, config: dict):
        super().__init__(session, config)
        self.payloads = self.config.get('payloads', [])

    def _get_selenium_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Chạy ngầm
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        # Quan trọng: Tắt XSS Auditor của Chrome cũ (nếu có) để test chính xác hơn
        chrome_options.add_argument("--disable-xss-auditor")

        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(10)
        return driver

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []

        # Chỉ test DOM XSS nếu URL có tham số hoặc fragment (#)
        parsed = urlparse(url)
        if not parsed.query and not parsed.fragment:
            return vulns

        # Filter các file tĩnh
        if any(url.endswith(ext) for ext in ['.jpg', '.png', '.css', '.pdf']):
            return vulns

        driver = None
        try:
            driver = self._get_selenium_driver()

            # 1. Test Injection vào Query Params (Source: location.search)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in self.payloads:
                        # Tạo URL test: ?param=payload
                        test_params = params.copy()
                        test_params[param] = payload
                        new_query = urlencode(test_params, doseq=True)
                        target_url = urlunparse(parsed._replace(query=new_query))

                        if self._check_alert(driver, target_url):
                            vulns.append(Vulnerability(
                                type='DOM-based XSS',
                                subcategory='Source: location.search',
                                url=target_url,
                                details={'parameter': param, 'payload': payload,
                                         'evidence': 'Javascript Alert executed'},
                                severity='High'
                            ))
                            break  # Tìm thấy 1 lỗi cho param này là đủ

            # 2. Test Injection vào Fragment/Hash (Source: location.hash)
            # Rất phổ biến trong các trang Single Page Application (Angular/React cũ)
            for payload in self.payloads:
                # Tạo URL test: #payload
                target_url = urlunparse(parsed._replace(fragment=payload))

                if self._check_alert(driver, target_url):
                    vulns.append(Vulnerability(
                        type='DOM-based XSS',
                        subcategory='Source: location.hash',
                        url=target_url,
                        details={'payload': payload, 'evidence': 'Javascript Alert executed via URI Fragment'},
                        severity='High'
                    ))
                    break

        except Exception as e:
            pass  # Selenium error handling
        finally:
            if driver:
                driver.quit()

        return vulns

    def _check_alert(self, driver, url):
        """Mở URL và kiểm tra xem có Alert dialog xuất hiện không"""
        try:
            driver.get(url)
            # Chờ một chút để JS thực thi
            time.sleep(1)

            # Kiểm tra Alert
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()  # Đóng alert để không treo

            # Xác nhận alert này do payload của mình tạo ra (thường payload chứa số đặc biệt)
            # Ở đây payload thường là <script>alert(1)</script> -> check text == '1'
            if 'XSS' in alert_text or '1' in alert_text:
                return True

        except (NoAlertPresentException, TimeoutException, UnexpectedAlertPresentException):
            # UnexpectedAlertPresentException có thể xảy ra ngay khi driver.get() nếu alert hiện quá nhanh
            return True if "UnexpectedAlertPresentException" in str(locals().get('e', '')) else False
        except Exception:
            pass
        return False