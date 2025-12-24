from typing import List, Optional
import requests
from urllib.parse import urlparse, urljoin

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class AccessControlTester(BaseTester):
    def __init__(self, session: requests.Session, config: dict):
        super().__init__(session, config)
        self.paths_to_test = self.config.get('paths', [])
        self.SEVERITY_MAP = {
            'Privilege Escalation': 'Critical',
            'Admin/Privileged Endpoint Exposure': 'Critical',
            'Potential IDOR': 'High',
            'Unauthenticated Access': 'High',
            'Sensitive File Exposure': 'High',
            'Method-Based Access Control Bypass': 'High',
            'Forced Browsing': 'Medium',
            'Directory Listing Enabled': 'Medium'
        }

        # Indicators that a page is just a login form (Auth Challenge)
        self.LOGIN_INDICATORS = [
            'login', 'signin', 'sign in', 'sign_in', 'log in',
            'authentication required', 'password', 'user id',
            'forgot password', 'csrf-token'
        ]

        # Extensions for Forced Browsing Confidence Logic
        self.HIGH_RISK_EXTS = ['.php', '.jsp', '.asp', '.aspx', '.xml', '.conf', '.json', '.env', '.sql']
        self.LOW_RISK_EXTS = ['.txt', '.md', '.css', '.js', '.png', '.jpg', '.html', '.ico']

    def _is_directory_listing(self, body: str) -> bool:
        """Detects directory listing based on content."""
        body_lower = body.lower()
        indicators = [
            'index of /',
            'parent directory',
            '<title>index of',
            'last modified',
            'description'
        ]
        return any(ind in body_lower for ind in indicators)

    def _is_auth_challenge(self, resp: requests.Response) -> bool:
        """Determines if the response is actually an authentication challenge."""
        # 1. Check Headers (Standard)
        # Note: requests headers are case-insensitive
        if resp.status_code == 401 or 'www-authenticate' in resp.headers:
            return True

        # 2. Check Redirects
        if resp.history and any(r.status_code in [301, 302, 303, 307] for r in resp.history):
            if any(x in resp.url.lower() for x in ['login', 'auth', 'signin']):
                return True

        # 3. Check Body Content (Heuristic)
        body_lower = resp.text.lower()
        if len(resp.text) < 2000 and any(k in body_lower for k in self.LOGIN_INDICATORS):
            return True

        return False

    def _determine_subcategory(self, path: str, resp: requests.Response, method_bypass: bool = False) -> str:
        path_lower = path.lower()

        if method_bypass:
            return "Method-Based Access Control Bypass"

        if self._is_directory_listing(resp.text):
            return "Directory Listing Enabled"

        # OWASP includes vertical escalation here
        if any(k in path_lower for k in ['admin', 'manager', 'config', 'dashboard', 'internal', 'root']):
            return "Privilege Escalation"

        if any(path_lower.endswith(ext) for ext in ['.git', '.env', '.bak', '.zip', '.sql', '.log', '.config']):
            return "Sensitive File Exposure"

        # Heuristic: URL contains indicators of direct object access
        if any(token in path_lower for token in ['id=', 'user_id=', '/user/', '/account/', '/order/', '/basket/']):
            return "Potential IDOR"

        # Forced Browsing (Hidden resources accessed directly)
        if '.' in path.split('/')[-1]:
            return "Forced Browsing"

        return "Unauthenticated Access"

    def _calculate_confidence(self, resp: requests.Response, is_auth: bool, category: str, path: str) -> float:
        """Calculates confidence score based on multiple heuristics."""
        confidence = 0.0

        # Strong signal: 200 OK means request succeeded
        if resp.status_code == 200:
            confidence += 0.4
        elif resp.status_code == 206:  # Partial content
            confidence += 0.3

        # Strong signal: Not a login page
        if not is_auth:
            confidence += 0.3

        # Content heuristic: Too short usually means empty or blocked by WAF/Filter
        if len(resp.text) > 500:
            confidence += 0.2

        # Category specific boosts
        if category in ["Privilege Escalation", "Potential IDOR"]:
            confidence += 0.1

        # Adjust confidence for Forced Browsing extensions
        if category == "Forced Browsing":
            path_lower = path.lower()
            if any(path_lower.endswith(ext) for ext in self.HIGH_RISK_EXTS):
                confidence += 0.2
            elif any(path_lower.endswith(ext) for ext in self.LOW_RISK_EXTS):
                confidence -= 0.3

        return min(confidence, 1.0)  # Cap at 1.0

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed_url = urlparse(url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if not self.paths_to_test:
            return vulns

        for path in self.paths_to_test:
            test_url = urljoin(base, path)

            try:
                # Use self.fetch from BaseTester (assuming it wraps session.get/request)
                resp = self.fetch(test_url, allow_redirects=True)
                if not resp:
                    continue

                # --- 1. Status Code Handling ---
                # Explicit denial or server error -> Skip. Focus on 200/206
                if resp.status_code in [401, 403] or resp.status_code >= 500:
                    continue

                # --- 2. Response Length Heuristic ---
                if len(resp.text) < 50:
                    continue

                # --- 3. Login Detection (Auth Challenge) ---
                is_auth_challenge = self._is_auth_challenge(resp)

                # --- 4. Method-Based Access Control Bypass Check ---
                method_bypass_detected = False
                sensitive_keywords = ['admin', 'config', 'api', 'internal', 'dashboard']

                # Only check method bypass if endpoint looks sensitive AND accessible via GET
                if (resp.status_code == 200
                        and not is_auth_challenge
                        and any(k in path.lower() for k in sensitive_keywords)):
                    try:
                        # Attempt POST request to see if it's blocked
                        post_resp = self.session.post(test_url, data={}, timeout=5, allow_redirects=False)
                        # Strong signal: POST explicitly forbidden while GET allowed
                        if post_resp.status_code == 403:
                            method_bypass_detected = True
                    except Exception:
                        pass

                # --- 5. Determine Subcategory ---
                subcategory = self._determine_subcategory(path, resp, method_bypass_detected)

                # --- 6. Calculate Confidence ---
                confidence_score = self._calculate_confidence(resp, is_auth_challenge, subcategory, path)

                # Thresholding
                confidence_level = 'Low'
                if confidence_score >= 0.8:
                    confidence_level = 'High'
                elif confidence_score >= 0.5:
                    confidence_level = 'Medium'
                else:
                    # Skip low confidence noise
                    continue

                # --- 7. Determine Severity ---
                severity = self.SEVERITY_MAP.get(subcategory, 'Medium')

                # Description construction
                desc = (
                    f"Accessible endpoint detected ({subcategory}). "
                    f"Status: {resp.status_code}, Length: {len(resp.text)}. "
                )
                if subcategory == "Potential IDOR":
                    desc += "Contains object identifiers in URL. Verify if user authorization is checked."
                elif is_auth_challenge:
                    desc += " Note: Page contains login indicators but returned 200 OK."

                vulns.append(Vulnerability(
                    type='Broken Access Control',
                    subcategory=subcategory,
                    url=test_url,
                    details={
                        'status_code': resp.status_code,
                        'confidence_score': round(confidence_score, 2),
                        'confidence_level': confidence_level,
                        'evidence': resp.text[:200],  # First 200 chars as evidence
                        'is_auth_challenge': is_auth_challenge
                    },
                    severity=severity
                ))

            except Exception:
                continue

        return vulns