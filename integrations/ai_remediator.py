# integrations/ai_remediator.py
import ollama
import json
import logging

logger = logging.getLogger(__name__)

# Tên mô hình đã tải về
MODEL_NAME = 'codellama:7b'


def generate_remediation(vulnerability_type: str, code_snippet: str, target_language: str = "php") -> dict:
    """
    Sử dụng Local LLM (Ollama) để tạo hướng dẫn sửa lỗi.

    Args:
        vulnerability_type (str): Loại lỗ hổng (ví dụ: 'SQL Injection', 'XSS').
        code_snippet (str): Đoạn code hoặc HTTP request/response liên quan.
        target_language (str): Ngôn ngữ lập trình của mục tiêu (ví dụ: 'php', 'nodejs', 'java').

    Returns:
        dict: Chứa 'explanation' và 'fixed_code'.
    """
    if not code_snippet:
        return {}

    # --- Xây dựng Prompt (Câu lệnh) cho AI ---
    # Đây là bước quan trọng nhất để AI trả về kết quả chất lượng.
    prompt = f"""
    You are a senior security engineer providing a code fix for a vulnerability.
    Your task is to analyze the vulnerability and provide a clear, concise, and secure code remediation.

    **Vulnerability Type:** {vulnerability_type}
    **Target Language:** {target_language}

    **Vulnerable Code Snippet / Evidence:**
    ```
    {code_snippet}
    ```

    **Your Response MUST be in JSON format with two keys:**
    1.  `explanation`: A brief explanation (in English) of WHY the code is vulnerable and HOW the fix works.
    2.  `fixed_code`: The corrected, secure code snippet.

    **Example JSON Response:**
    {{
        "explanation": "The original code was vulnerable to SQL Injection because it directly concatenated user input into the SQL query. The fix uses parameterized queries (prepared statements) to separate the query logic from the user data, preventing injection.",
        "fixed_code": "..."
    }}

    **Provide the JSON response now:**
    """

    try:
        print(f"  [AI Remediator] Generating fix for {vulnerability_type} in {target_language}...")

        # Gọi API của Ollama
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt}],
            format='json'  # Yêu cầu Ollama trả về JSON
        )

        # Ollama trả về một dictionary, chúng ta lấy nội dung
        content = response['message']['content']

        # Parse chuỗi JSON trả về
        remediation_data = json.loads(content)

        print(f"  [AI Remediator] Fix generated successfully.")
        return remediation_data

    except Exception as e:
        logger.error(f"Error communicating with Ollama: {e}")
        return {"error": str(e)}