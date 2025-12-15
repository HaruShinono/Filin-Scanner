# integrations/sqlmap_scanner.py
import re
from .tool_runner import run_command


def run_sqlmap(target_url: str, cookies: str = None) -> list:
    """
    Chạy sqlmap để kiểm tra lỗ hổng SQL Injection.
    Sử dụng chế độ --forms để tự động tìm form và --batch để không hỏi người dùng.
    """
    findings = []

    # Cấu hình lệnh sqlmap
    # --batch: Chạy tự động, không hỏi yes/no
    # --forms: Tự động parse các form trên trang HTML
    # --level 1 --risk 1: Chỉ quét cơ bản, an toàn, tránh làm hỏng DB
    # --random-agent: Giả mạo User-Agent
    # --dbs: Nếu hack được thì thử liệt kê database (bằng chứng thép)
    command = [
        'sqlmap',
        '-u', target_url,
        '--batch',
        '--random-agent',
        '--forms',
        '--level', '1',
        '--risk', '1',
        '--dbs'
    ]

    if cookies:
        command.extend(['--cookie', cookies])

    print(f"Running sqlmap on {target_url}...")

    # Chạy lệnh (sqlmap có thể chạy lâu, ở đây ta để mặc định timeout của hệ thống)
    # Trong thực tế, bạn có thể muốn set timeout cho subprocess
    output = run_command(command)

    if not output:
        return findings

    # Phân tích output bằng Regex để tìm thông tin lỗ hổng
    # Sqlmap thường xuất ra dạng:
    # Parameter: id (GET)
    #     Type: boolean-based blind
    #     Title: AND boolean-based blind - WHERE or HAVING clause

    # Regex để bắt khối thông tin này
    vuln_pattern = re.compile(
        r"Parameter: (?P<param>.*?)\n\s+Type: (?P<type>.*?)\n\s+Title: (?P<title>.*?)",
        re.MULTILINE | re.DOTALL
    )

    # Tìm các đoạn văn bản khớp
    # Do output sqlmap khá dài và phức tạp, ta sẽ quét từng khối

    # Kiểm tra xem có dòng báo lỗ hổng không
    if "sqlmap identified the following injection point" in output or "Parameter:" in output:
        # Tách output thành các đoạn dựa trên từ khóa "Parameter:"
        parts = output.split("Parameter: ")

        # Bỏ qua phần đầu tiên (header của sqlmap)
        for part in parts[1:]:
            lines = part.split('\n')
            param_name = lines[0].strip()  # Dòng đầu tiên sau split là tên tham số

            # Tìm các kiểu tấn công thành công trong đoạn này
            current_vuln = {}
            for line in lines:
                line = line.strip()
                if line.startswith("Type:"):
                    current_vuln['type'] = line.replace("Type:", "").strip()
                elif line.startswith("Title:"):
                    current_vuln['title'] = line.replace("Title:", "").strip()
                    # Khi tìm thấy Title, nghĩa là đã đủ 1 bộ thông tin (Param + Type + Title)
                    # Lưu lại và reset
                    if current_vuln:
                        findings.append({
                            'parameter': param_name,
                            'type': current_vuln.get('type'),
                            'title': current_vuln.get('title'),
                            'payload_info': 'See full logs for payload details'
                        })
                        current_vuln = {'type': current_vuln.get('type')}  # Giữ lại type cho title tiếp theo

    # Kiểm tra xem có dump được tên database không (Bằng chứng khai thác thành công)
    dbs = []
    if "available databases" in output:
        # Logic đơn giản để lấy tên DB (thường nằm sau dòng available databases [...]:)
        db_pattern = re.search(r"available databases \[\d+\]:\n(.*?)\n\n", output, re.DOTALL)
        if db_pattern:
            dbs_text = db_pattern.group(1)
            dbs = [line.strip().replace('[*] ', '') for line in dbs_text.split('\n') if '[*]' in line]

    # Nếu tìm thấy lỗ hổng, tổng hợp lại kết quả
    final_results = []
    if findings:
        # Gộp tất cả findings vào 1 báo cáo duy nhất cho gọn, hoặc tách lẻ
        final_results.append({
            'findings': findings,
            'databases_found': dbs,
            'raw_output_snippet': output[-1000:]  # Lấy 1000 ký tự cuối làm bằng chứng
        })

    return final_results