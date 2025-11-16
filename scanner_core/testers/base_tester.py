import requests
from typing import Optional

class BaseTester:
    def __init__(self, session: requests.Session, config: dict = None):
        self.session = session
        # The config parameter is added for consistency, though the base class may not use it.
        self.config = config or {}
        self.cache = {}

    def test(self, url: str):
        raise NotImplementedError("Each tester must implement the 'test' method.")

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