import requests
from typing import Optional
from difflib import SequenceMatcher


class BaseTester:
    def __init__(self, session: requests.Session, config: dict = None):
        self.session = session
        self.config = config or {}
        self.cache = {}

    def fetch(self, url: str, **kwargs) -> Optional[requests.Response]:
        if url in self.cache:
            return self.cache[url]
        try:
            response = self.session.get(url, timeout=15, verify=False, **kwargs)
            self.cache[url] = response
            return response
        except requests.RequestException:
            self.cache[url] = None
            return None

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        if not text1 or not text2:
            return 0.0
        return SequenceMatcher(None, text1, text2).ratio()

    def _is_response_stable(self, url: str) -> bool:
        r1 = self.fetch(url)

        try:
            r2 = self.session.get(url, timeout=10, verify=False)
        except:
            return False

        if not r1 or not r2:
            return False

        return self._calculate_similarity(r1.text, r2.text) > 0.90