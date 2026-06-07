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
        search_query = f'affectedSoftware.name:"{service.lower()}" AND affectedSoftware.version:"{version}"'
        results = v_api.search.search_bulletins(query=search_query, limit=50)

        matched_cves = []
        for item in results:
            cve_id = item.get('id', 'N/A')
            title = item.get('title', 'Unknown Vulnerability')
            href = item.get('href', 'N/A')

            # Lấy mô tả ngắn gọn (tối đa 150 ký tự) để hiển thị tooltip trên web
            desc = item.get('description', '')
            desc_snippet = (desc[:150] + "...") if len(desc) > 150 else desc

            cvss_data = item.get('cvss3', item.get('cvss', {}))
            cvss_score = 0.0
            cvss_vector = "UNKNOWN"

            if isinstance(cvss_data, dict):
                cvss_score = float(cvss_data.get('score', cvss_data.get('value', 0.0)))
                cvss_vector = cvss_data.get('vector', 'UNKNOWN')

            # Đẩy cấu trúc JSON đầy đủ vào mảng
            matched_cves.append({
                "id": cve_id,
                "score": cvss_score,
                "vector": cvss_vector,
                "title": title,  # Lấy title đầy đủ, giao diện web sẽ tự động ngắt dòng
                "desc_snippet": desc_snippet,
                "href": href
            })

        matched_cves.sort(key=lambda x: x['score'], reverse=True)
        return matched_cves

    except Exception as e:
        logger.error(f"Lỗi truy vấn Vulners Component ({service} {version}): {e}")
        return []


def lookup_cve(cve_id: str) -> dict:
    try:
        v_api = get_vulners_api()
        res = v_api.search.search_bulletins(query=f'id:"{cve_id}"', limit=1)
        if res:
            item = res[0]
            title = item.get('title', 'Unknown')
            href = item.get('href', 'N/A')
            cvss_data = item.get('cvss3', item.get('cvss', {}))
            score = 0.0
            vector = "UNKNOWN"
            if isinstance(cvss_data, dict):
                score = float(cvss_data.get('score', cvss_data.get('value', 0.0)))
                vector = cvss_data.get('vector', 'UNKNOWN')
            return {"score": score, "vector": vector, "title": title, "href": href}
    except Exception as e:
        logger.error(f"Lỗi truy vấn Vulners CVE ({cve_id}): {e}")

    return {"score": 0.0, "vector": "UNKNOWN", "title": "N/A", "href": "N/A"}