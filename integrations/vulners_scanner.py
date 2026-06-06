# integrations/vulners_scanner.py
import vulners
import logging

logger = logging.getLogger(__name__)

VULNERS_API_KEY = ""


def get_vulners_api():
    if VULNERS_API_KEY:
        return vulners.VulnersApi(api_key=VULNERS_API_KEY)
    return vulners.VulnersApi()


def audit_component(service: str, version: str) -> list:
    """Tra cứu lỗ hổng chính xác theo tên và phiên bản phần mềm"""
    if not service or not version:
        return []

    try:
        v_api = get_vulners_api()
        # Truy vấn chính xác theo Affected Software của Vulners
        search_query = f'affectedSoftware.name:"{service.lower()}" AND affectedSoftware.version:"{version}"'

        results = v_api.search.search_bulletins(query=search_query, limit=50)

        matched_cves = []
        for item in results:
            cve_id = item.get('id', 'N/A')
            title = item.get('title', 'Không có tiêu đề')
            href = item.get('href', 'N/A')

            # Ưu tiên lấy điểm CVSS v3, nếu không có thì lấy v2
            cvss_data = item.get('cvss3', item.get('cvss', {}))
            cvss_score = 0.0
            cvss_vector = "UNKNOWN"

            if isinstance(cvss_data, dict):
                cvss_score = float(cvss_data.get('score', cvss_data.get('value', 0.0)))
                cvss_vector = cvss_data.get('vector', 'UNKNOWN')

            short_title = (title[:55] + "...") if len(title) > 55 else title

            matched_cves.append({
                "id": cve_id,
                "score": cvss_score,
                "vector": cvss_vector,
                "title": short_title,
                "href": href
            })

        # Sắp xếp từ cao xuống thấp
        matched_cves.sort(key=lambda x: x['score'], reverse=True)
        return matched_cves

    except Exception as e:
        logger.error(f"Lỗi truy vấn Vulners Component ({service} {version}): {e}")
        return []


def lookup_cve(cve_id: str) -> dict:
    """Dùng cho Nmap: Chỉ tra cứu điểm CVSS của 1 mã CVE cụ thể"""
    try:
        v_api = get_vulners_api()
        res = v_api.search.search_bulletins(query=f'id:"{cve_id}"', limit=1)
        if res:
            item = res[0]
            cvss_data = item.get('cvss3', item.get('cvss', {}))
            score = 0.0
            vector = "UNKNOWN"
            if isinstance(cvss_data, dict):
                score = float(cvss_data.get('score', cvss_data.get('value', 0.0)))
                vector = cvss_data.get('vector', 'UNKNOWN')
            return {"score": score, "vector": vector}
    except Exception as e:
        logger.error(f"Lỗi truy vấn Vulners CVE ({cve_id}): {e}")

    return {"score": 0.0, "vector": "UNKNOWN"}