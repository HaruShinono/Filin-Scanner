import json
from .tool_runner import run_command, is_tool_installed


def run_wappalyzer(target: str) -> dict | None:
    if not is_tool_installed('wappalyzer'):
        print("[-] Error: 'wappalyzer' is not installed.", flush=True)
        return None

    # wappalyzer trả về JSON trực tiếp qua stdout
    cmd = ['wappalyzer', target]
    output = run_command(cmd)

    if output:
        try:
            return json.loads(output)
        except Exception as e:
            print(f"Error parsing wappalyzer output: {e}", flush=True)
    return None