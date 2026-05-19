# utils/cvss_calc.py
from cvss import CVSS4

def parse_and_calculate_cvss(vector_str: str):
    if not vector_str:
        return None, None

    try:
        # Xóa các khoảng trắng thừa nếu có
        vector_str = vector_str.strip()

        # Chỉ xử lý CVSS 4.0 theo yêu cầu đồ án
        if vector_str.startswith("CVSS:4.0"):
            c = CVSS4(vector_str)
            score = c.scores()[0]
            severity = c.severities()[0]
            return round(score, 1), severity.capitalize()

        return None, None
    except Exception as e:
        print(f"Error parsing CVSS vector '{vector_str}': {e}")
        return None, None