import re
from .tool_runner import run_command, is_tool_installed


def run_sqlmap(target_url: str, cookies: str = None) -> list:
    findings = []

    if not is_tool_installed('sqlmap'):
        print("[-] Error: 'sqlmap' is not installed or not in PATH. Skipping phase.", flush=True)
        return findings

    command = [
        'sqlmap',
        '-u', target_url,
        '--batch',
        '--random-agent',
        '--forms',
        '--level', '1',
        '--risk', '1',
        '--dbs',
        '--disable-coloring'
    ]

    if cookies:
        command.extend(['--cookie', cookies])

    print(f"[*] Starting sqlmap on {target_url} (This may take a while)...", flush=True)

    output = run_command(command)

    if not output:
        print(f"[-] sqlmap finished with no output or error.", flush=True)
        return findings

    if "sqlmap identified the following injection point" in output or "Parameter:" in output:
        parts = output.split("Parameter: ")

        for part in parts[1:]:
            lines = part.split('\n')
            param_name = lines[0].strip()

            current_vuln = {}
            for line in lines:
                line = line.strip()
                if line.startswith("Type:"):
                    current_vuln['type'] = line.replace("Type:", "").strip()
                elif line.startswith("Title:"):
                    current_vuln['title'] = line.replace("Title:", "").strip()

                    if current_vuln:
                        findings.append({
                            'parameter': param_name,
                            'type': current_vuln.get('type'),
                            'title': current_vuln.get('title'),
                            'payload_info': 'See full logs for payload details'
                        })
                        current_vuln = {'type': current_vuln.get('type')}

    dbs = []
    if "available databases" in output:
        db_pattern = re.search(r"available databases \[\d+\]:\n(.*?)\n\n", output, re.DOTALL)
        if db_pattern:
            dbs_text = db_pattern.group(1)
            dbs = [line.strip().replace('[*] ', '') for line in dbs_text.split('\n') if '[*]' in line]

    final_results = []
    if findings:
        print(f"[+] sqlmap FOUND vulnerabilities!", flush=True)
        final_results.append({
            'findings': findings,
            'databases_found': dbs,
            'raw_output_snippet': output[-2000:]
        })
    else:
        print(f"[*] sqlmap finished. No vulnerabilities found.", flush=True)

    return final_results