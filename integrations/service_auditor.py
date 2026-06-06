# integrations/service_auditor.py
import vulners
import logging

logger = logging.getLogger(__name__)

VULNERS_API_KEY = ""

def get_vulners_api():
    if VULNERS_API_KEY:
        return vulners.VulnersApi(api_key=VULNERS_API_KEY)
    return vulners.VulnersApi()

def audit_service_version(service_name: str, version: str) -> list:
    if not service_name or not version:
        return []

    try:
        v_api = get_vulners_api()
        query = f'"{service_name}" "{version}" type:cve'
        results = v_api.search(query, limit=10)

        findings = []
        for res in results:
            cve_id = res.get('id')
            exploits = find_exploits_for_cve(v_api, cve_id)

            # Lấy thông tin CVSS trực tiếp từ dữ liệu Vulners (Ưu tiên CVSS v3)
            cvss_data = res.get('cvss3', res.get('cvss', {}))
            score = cvss_data.get('score', cvss_data.get('value', 0.0))
            vector = cvss_data.get('vector', 'UNKNOWN')

            findings.append({
                'id': cve_id,
                'title': res.get('title'),
                'score': float(score) if score is not None else 0.0,
                'vector': vector,
                'description': res.get('description', ''),
                'href': res.get('href'),
                'exploits': exploits
            })

        return findings

    except Exception as e:
        logger.error(f"Error auditing service {service_name} {version}: {e}")
        return []

def find_exploits_for_cve(api_instance, cve_id: str) -> list:
    try:
        query = f"{cve_id} (bulletinFamily:exploit OR type:github)"
        results = api_instance.search(query, limit=3)

        exploits = []
        for res in results:
            exploits.append({
                'id': res.get('id'),
                'title': res.get('title'),
                'url': res.get('href'),
                'source': res.get('type')
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
            cvss_data = res.get('cvss3', res.get('cvss', {}))
            score = cvss_data.get('score', cvss_data.get('value', 0.0))
            findings.append({
                'id': res.get('id'),
                'title': res.get('title'),
                'score': float(score) if score is not None else 0.0
            })
        return findings
    except Exception:
        return []