# integrations/waf_bypass_scanner.py
import subprocess
import os
import re


def run_waf_bypass(target_url: str) -> list:
    """
    Executes the third-party WAF bypass tool on the target URL
    and parses its stdout for findings.
    """
    findings = []

    # Locate the cloned repository's path relative to this file
    tool_dir = os.path.join(os.path.dirname(__file__), 'waf-bypass-tool')
    script_path = os.path.join(tool_dir, 'main.py')

    if not os.path.exists(script_path):
        print("[-] Error: 'waf-bypass-tool' is not installed in integrations/. Skipping.", flush=True)
        return findings

    # Construct command execution
    # --url: specifies target
    # We use python3 to execute its entrypoint
    command = [
        'python3', script_path,
        '--url', target_url
    ]

    print(f"[*] Starting WAF bypass auditing on {target_url}...", flush=True)

    try:
        # Run subprocess using tool_dir as working directory so internal imports resolve
        result = subprocess.run(
            command,
            cwd=tool_dir,
            capture_output=True,
            text=True,
            timeout=300  # Limit execution to 5 minutes to prevent hanging
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        print(f"[-] WAF bypass verification timed out for {target_url}", flush=True)
        return findings
    except Exception as e:
        print(f"[-] Error executing waf-bypass-tool: {e}", flush=True)
        return findings

    if not output:
        return findings

    # Parse stdout for behavioral indicators
    if "WAF Detected" in output or "WAF type:" in output:
        # Extract WAF type if printed
        waf_type = "Unknown"
        type_match = re.search(r"WAF type:\s*([a-zA-Z0-9_-]+)", output, re.IGNORECASE)
        if type_match:
            waf_type = type_match.group(1)

        findings.append({
            'tool': 'waf-bypass-tool',
            'finding_type': 'WAF Detected',
            'details': {
                'issue': f"Active Web Application Firewall ({waf_type}) identified.",
                'raw_output': output[:500]  # Save head logs
            }
        })

    # Search for successful mutations or bypass patterns reported by the tool
    success_matches = re.findall(r"\[\+\]\s*Bypass\s*successful.*", output, re.IGNORECASE)
    for match in success_matches:
        findings.append({
            'tool': 'waf-bypass-tool',
            'finding_type': 'Potential WAF Bypass',
            'details': {
                'issue': 'A mutated payload pattern successfully bypassed the WAF filter.',
                'evidence': match.strip()
            }
        })

    return findings