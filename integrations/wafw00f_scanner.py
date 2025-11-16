# integrations/wafw00f_scanner.py
import json
from .tool_runner import run_command


def run_wafw00f(target_url: str) -> dict | None:
    # -f json: Output dạng JSON
    # -o -: Ghi ra stdout
    command = ['wafw00f', target_url, '-f', 'json', '-o', '-']
    json_output = run_command(command)

    if not json_output:
        return None

    try:
        results = json.loads(json_output)
        if results and isinstance(results, list):
            results = results[0]  # wafw00f trả về một list chứa một dict

        if results.get("firewall") and results.get("firewall") != "None":
            return {
                "firewall": results.get("firewall"),
                "manufacturer": results.get("manufacturer")
            }
    except (json.JSONDecodeError, IndexError) as e:
        print(f"Error parsing wafw00f JSON output: {e}")

    return None