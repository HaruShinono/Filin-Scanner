# integrations/dnsrecon_scanner.py
import json
import tempfile
import os
from .tool_runner import run_command

def run_dnsrecon(domain: str) -> list:
    #Runs dnsrecon to gather DNS records (A, AAAA, MX, NS, TXT, etc.).
    findings = []
    # Create a temporary file to store JSON output
    # dnsrecon works best when writing JSON to a file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
        output_path = tmp_file.name

    try:
        # -d: Domain
        # -j: JSON output path
        # --lifetime 5: Time to wait for a server to respond
        command = ['dnsrecon', '-d', domain, '-j', output_path, '--lifetime', '5']

        # We don't need to capture stdout here as we are reading the file
        run_command(command)

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    # dnsrecon returns a list of records
                    for record in data:
                        # Filter out irrelevant records or empty ones
                        if record.get('type') and record.get('address') or record.get('mname') or record.get('target'):
                            findings.append(record)
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        print(f"Error running dnsrecon: {e}")
    finally:
        # Cleanup temp file
        if os.path.exists(output_path):
            os.remove(output_path)

    return findings