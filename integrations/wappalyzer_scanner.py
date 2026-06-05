# integrations/wappalyzer_scanner.py
import urllib3
import requests
from Wappalyzer import Wappalyzer, WebPage
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_wappalyzer(target: str) -> dict | None:
    print(f"  [Wappalyzer] Scanning {target} using python-Wappalyzer...", flush=True)
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'ngrok-skip-browser-warning': 'true'
        }
        resp = requests.get(target, headers=headers, timeout=10, verify=False)
        webpage = WebPage.new_from_response(resp)
        wappalyzer = Wappalyzer.latest()
        results = wappalyzer.analyze_with_versions_and_categories(webpage)  # 1.2.2
        return results
    except Exception as e:
        print(f"  [Wappalyzer] Error running python-Wappalyzer: {e}", flush=True)
        return None