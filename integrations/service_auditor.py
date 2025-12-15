# integrations/service_auditor.py
import vulners
import logging

logger = logging.getLogger(__name__)

# Đăng ký API Key tại https://vulners.com/ (Khuyên dùng để không bị giới hạn)
VULNERS_API_KEY = ""


def get_vulners_api():
    if VULNERS_API_KEY:
        return vulners.Vulners(api_key=VULNERS_API_KEY)
    return vulners.Vulners()


def audit_service_version(service_name: str, version: str) -> list:
    if not service_name or not version:
        return []

    try:
        v_api = get_vulners_api()
        query = f'"{service_name}" "{version}" type:cve'
        results = v_api.search(query, limit=5)

        findings = []
        for res in results:
            cve_id = res.get('id')

            # [MỚI] Tìm mã khai thác (Exploit) cho CVE này
            exploits = find_exploits_for_cve(v_api, cve_id)

            findings.append({
                'id': cve_id,
                'title': res.get('title'),
                'score': res.get('cvss', {}).get('score', 0.0),
                'vector': res.get('cvss', {}).get('vector', 'UNKNOWN'),
                'description': res.get('description', ''),
                'href': res.get('href'),
                'exploits': exploits  # Danh sách các exploit tìm được
            })

        return findings

    except Exception as e:
        logger.error(f"Error auditing service {service_name} {version}: {e}")
        return []


def find_exploits_for_cve(api_instance, cve_id: str) -> list:
    try:
        # Tìm các bài viết loại 'exploitdb', 'packetstorm', 'github' liên quan đến CVE
        query = f"{cve_id} (bulletinFamily:exploit OR type:github)"
        results = api_instance.search(query, limit=3)

        exploits = []
        for res in results:
            exploits.append({
                'id': res.get('id'),
                'title': res.get('title'),
                'url': res.get('href'),
                'source': res.get('type')  # exploitdb, packetstorm, etc.
            })
        return exploits
    except Exception:
        return []


def audit_cms_component(component_name: str, version: str, cms_type="wordpress") -> list:
    try:
        v_api = get_vulners_api()
        query = f'"{cms_type}" plugin "{component_name}" "{version}" type:cve'
        results = v_api.search(query, limit=5)

        findings = []
        for res in results:
            findings.append({
                'id': res.get('id'),
                'title': res.get('title'),
                'score': res.get('cvss', {}).get('score', 0.0)
            })
        return findings
    except Exception:
        return []