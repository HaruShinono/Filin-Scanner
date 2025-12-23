import ollama
import json
import logging

logger = logging.getLogger(__name__)

# Ensure you have pulled this model via: ollama pull codellama:7b
MODEL_NAME = 'codellama:7b'


def generate_remediation(vulnerability_type: str, code_snippet: str, target_language: str = "php") -> dict:
    """
    Generates a specific code fix and explanation for a single vulnerability.
    """
    if not code_snippet:
        return {}

    # Prompt engineering to enforce JSON output
    prompt = f"""
    You are a senior security engineer. Analyze this vulnerability and provide a secure code fix.

    **Vulnerability:** {vulnerability_type}
    **Language:** {target_language}
    **Context:**
    ```
    {code_snippet}
    ```

    **Response Format (JSON only):**
    {{
        "explanation": "Brief explanation of the flaw and the fix.",
        "fixed_code": "The corrected code snippet."
    }}
    """

    try:
        print(f"  [AI] Generating fix for {vulnerability_type}...", flush=True)

        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt}],
            format='json'  # Force JSON mode
        )

        content = response['message']['content']
        return json.loads(content)

    except Exception as e:
        logger.error(f"Ollama error (remediation): {e}")
        return {}


def generate_overall_analysis(target_url: str, vuln_summary: list) -> dict:
    """
    Generates a high-level executive summary based on all found vulnerabilities.
    """
    if not vuln_summary:
        return {}

    # Format vulnerability list for the prompt
    vuln_text = "\n".join([f"- {v['type']} ({v['severity']})" for v in vuln_summary])

    prompt = f"""
    You are a CISO. Analyze the security posture of {target_url} based on these findings:

    {vuln_text}

    **Response Format (JSON only):**
    {{
        "risk_score": "Integer 0-100 (100 is critical risk)",
        "executive_summary": "2-3 sentences summarizing the overall security status.",
        "top_priorities": ["Action 1", "Action 2", "Action 3"],
        "strategic_recommendations": "Long-term security advice."
    }}
    """

    try:
        print(f"  [AI] Generating Executive Summary...", flush=True)

        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt}],
            format='json'
        )

        return json.loads(response['message']['content'])

    except Exception as e:
        logger.error(f"Ollama error (summary): {e}")
        return {}