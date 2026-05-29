import json
import subprocess
import tempfile
import os
from .tool_runner import run_command, is_tool_installed

def run_whatweb(target: str) -> dict | None:
    if not is_tool_installed('whatweb'):
        print("[-] Error: 'whatweb' is not installed.", flush=True)
        return None

    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
        out_file = tmp.name

    # -q: Quiet mode
    # --log-json: Xuất định dạng JSON ra file tạm
    cmd = ['whatweb', '--color=never', '-q', f'--log-json={out_file}', target]
    run_command(cmd)

    result_data = None
    try:
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    result_data = data[0]
    except Exception as e:
        print(f"Error parsing whatweb output: {e}", flush=True)
    finally:
        if os.path.exists(out_file):
            os.remove(out_file)

    return result_data