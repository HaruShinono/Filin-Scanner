# utils/cvss_calc.py
import math

def round_up(value: float) -> float:
    int_val = round(value * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000
    else:
        return (math.floor(int_val / 10000) + 1) / 10

# Trọng số các chỉ số khai thác (Exploitability Metrics)
AV_WEIGHTS = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
AC_WEIGHTS = {'L': 0.77, 'H': 0.44}
PR_WEIGHTS = {
    'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # Khi Scope Không đổi (Unchanged)
    'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}  # Khi Scope Thay đổi (Changed)
}
UI_WEIGHTS = {'N': 0.85, 'R': 0.62}

# Trọng số các chỉ số ảnh hưởng (Impact Metrics)
IMPACT_WEIGHTS = {'H': 0.56, 'L': 0.22, 'N': 0.0}


def calculate_cvss31_base(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
    # 1. Tính toán giá trị trung gian Exploitability (Tính dễ khai thác)
    exploitability = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * PR_WEIGHTS[s][pr] * UI_WEIGHTS[ui]

    # 2. Tính toán giá trị trung gian ISS (Impact Sub-Score)
    iss = 1 - ((1 - IMPACT_WEIGHTS[c]) * (1 - IMPACT_WEIGHTS[i]) * (1 - IMPACT_WEIGHTS[a]))

    # 3. Tính toán Impact dựa trên trạng thái của Scope (S)
    if s == 'U':  # Unchanged
        impact = 6.42 * iss
    else:  # Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    if impact <= 0:
        return 0.0

    if s == 'U':
        base_score = round_up(min((impact + exploitability), 10.0))
    else:
        base_score = round_up(min(1.08 * (impact + exploitability), 10.0))

    return base_score


def get_severity(score: float) -> str:
    """Phân loại mức độ nghiêm trọng dựa trên thang điểm CVSS v3.1."""
    if score == 0.0:
        return "None"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    else:
        return "Critical"


def map_metrics(vuln_type: str, subcategory: str, has_auth: bool):
    av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'N', 'N', 'N'

    vt = vuln_type.lower().strip()
    sub = (subcategory or "").lower().strip()

    if "sql injection" in vt or "sqli" in vt:
        if "authentication bypass" in sub:
            # Bypass được đăng nhập thông qua API => Ảnh hưởng cực kỳ nghiêm trọng, scope thay đổi
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'C', 'H', 'H', 'H'
        elif any(method in sub for method in ["post", "put", "patch", "delete"]):
            # SQLi qua POST/PUT thường gây sửa đổi dữ liệu DB trực tiếp (Confidentiality & Integrity High)
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'H', 'N'
        elif "error-based" in sub:
            # Đọc dữ liệu qua thông tin lỗi, khó ghi đè DB trực tiếp (Confidentiality High, Integrity Low)
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'L', 'N'
        elif "time-based" in sub:
            # Phản hồi dựa trên độ trễ, có nguy cơ gây tắc nghẽn DB nhẹ (Availability Low)
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'N', 'L'
        else:  # Boolean-based / Mặc định
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'L', 'N'

    elif "local file inclusion" in vt or "lfi" in vt:
        if any(kw in sub for kw in ["wrapper", "environ"]):
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'C', 'H', 'H', 'H'
        elif "project configuration" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'N', 'N'
        else:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'N', 'N'

    elif "cross-site scripting" in vt or "xss" in vt:
        if "stored" in sub:
            # Lưu trữ trên Server ảnh hưởng rộng hơn
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'R', 'C', 'L', 'L', 'N'
        elif "dom-based" in sub:
            # Xử lý thuần trên browser (Scope Unchanged)
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'R', 'U', 'L', 'L', 'N'
        else:  # Reflected / API Reflected
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'R', 'C', 'L', 'L', 'N'

    elif "broken access control" in vt:
        if "privilege escalation" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'L', 'N', 'C', 'H', 'H', 'H'
        elif "idor" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'L', 'N', 'U', 'H', 'N', 'N'
        elif "cswsh" in sub or "websocket hijacking" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'R', 'C', 'H', 'H', 'N'
        elif "sensitive file" in sub or "directory exposure" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'H', 'N', 'N'
        else:  # Unauthenticated Access / Forced Browsing
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'L', 'N', 'N'

    elif "xml external entity" in vt or "xxe" in vt:
        if "external dtd" in sub:
            # SSRF/File leak rộng hơn
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'C', 'H', 'H', 'N'
        else:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'H', 'N', 'N'

    elif "server-side request forgery" in vt or "ssrf" in vt:
        if "metadata" in sub or "gcp" in sub:
            # Đọc được Cloud Access token -> Thường chiếm quyền dịch vụ Cloud (C: High, Scope: Changed)
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'C', 'H', 'N', 'N'
        else:
            # Quét mạng nội bộ (C: Low, I: Low)
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'L', 'L', 'N'

    elif "template injection" in vt or "ssti" in vt:
        if "command execution" in sub or "rce" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'C', 'H', 'H', 'H'
        else:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', ('L' if has_auth else 'N'), 'N', 'U', 'H', 'N', 'N'

    elif "security misconfiguration" in vt:
        if "cors" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'R', 'U', 'L', 'L', 'N'
        else:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'L', 'N', 'N'


    elif "cross-site request forgery" in vt or "csrf" in vt:
        av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'R', 'U', 'N', 'L', 'N'

    elif "cryptographic failure" in vt or "sensitive data exposure" in vt:
        if "private key" in sub or "credentials" in sub or "stripe" in sub:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'H', 'N', 'N'
        else:
            av, ac, pr, ui, s, c, i, a = 'N', 'L', 'N', 'N', 'U', 'L', 'N', 'N'

    return av, ac, pr, ui, s, c, i, a


def generate_cvss31_vector(av, ac, pr, ui, s, c, i, a) -> str:
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def calculate_vulnerability_cvss(vuln_type: str, subcategory: str, has_auth: bool):
    av, ac, pr, ui, s, c, i, a = map_metrics(vuln_type, subcategory, has_auth)
    score = calculate_cvss31_base(av, ac, pr, ui, s, c, i, a)
    vector = generate_cvss31_vector(av, ac, pr, ui, s, c, i, a)
    severity = get_severity(score)
    return score, vector, severity