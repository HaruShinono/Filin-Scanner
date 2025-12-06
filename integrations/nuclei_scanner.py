# integrations/nuclei_scanner.py
import json
import tempfile
import os
from .tool_runner import run_command


def run_nuclei(target: str) -> list:
    """
    Chạy Nuclei scanner và trả về danh sách các lỗ hổng tìm được.
    """
    findings = []

    # Tạo file tạm để chứa kết quả JSON
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
        output_path = tmp_file.name

    try:
        # Nuclei command:
        # -u: Target URL
        # -json-export: Xuất ra JSON
        # -es info: Bỏ qua các log info, chỉ lấy lỗ hổng (low, medium, high, critical)
        # Nếu muốn lấy hết thì bỏ "-es info"
        command = [
            'nuclei',
            '-u', target,
            '-json-export', output_path,
            '-disable-update-check'  # Tắt update check để chạy nhanh hơn
        ]

        print(f"Running Nuclei on {target}...")
        run_command(command)

        if os.path.exists(output_path):
            with open(output_path, 'r', encoding='utf-8') as f:
                # Nuclei ghi mỗi dòng là một JSON object (JSONL)
                for line in f:
                    try:
                        if not line.strip(): continue
                        data = json.loads(line)

                        # Chỉ lấy những cái có info.name
                        if 'info' in data:
                            findings.append({
                                'type': data['info'].get('name', 'Unknown Nuclei Finding'),
                                'severity': data['info'].get('severity', 'low').title(),  # Low, Medium, High
                                'url': data.get('matched-at', target),
                                'details': {
                                    'template_id': data.get('template-id'),
                                    'description': data['info'].get('description', ''),
                                    'matcher_name': data.get('matcher-name', ''),
                                    'curl_command': data.get('curl-command', '')
                                }
                            })
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error running Nuclei: {e}")
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)

    return findings