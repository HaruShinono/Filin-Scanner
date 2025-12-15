import json
from .tool_runner import run_command


def run_wafw00f(target_url: str) -> dict | None:
    command = ['wafw00f', target_url, '-f', 'json', '-o', '-']
    json_output = run_command(command)

    if not json_output:
        return None

    try:
        data = json.loads(json_output)

        result = None
        if isinstance(data, list) and len(data) > 0:
            result = data[0]
        elif isinstance(data, dict):
            result = data

        if result and isinstance(result, dict):
            firewall = result.get("firewall")
            if firewall and firewall != "None":
                return {
                    "firewall": firewall,
                    "manufacturer": result.get("manufacturer")
                }
    except (json.JSONDecodeError, IndexError, AttributeError) as e:
        print(f"Error parsing wafw00f JSON output: {e}")

    return None