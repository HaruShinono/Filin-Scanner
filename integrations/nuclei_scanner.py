import json
import tempfile
import os
import yaml
from .tool_runner import run_command, is_tool_installed

templates_updated = False


def load_nuclei_config():
    try:
        with open('config/nucleiconfig.yml', 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load nucleiconfig.yml: {e}. Using defaults.", flush=True)
        return {}


def run_nuclei(target: str) -> list:
    global templates_updated
    findings = []

    config = load_nuclei_config()

    if not is_tool_installed('nuclei'):
        print("[-] Error: 'nuclei' is not installed. Skipping Nuclei phase.", flush=True)
        return findings

    if config.get('update_templates', False) and not templates_updated:
        print("  [Nuclei] Checking for template updates...", flush=True)
        run_command(['nuclei', '-ut'])
        templates_updated = True

    command = [
        'nuclei',
        '-u', target,
        '-disable-update-check'
    ]

    severities = config.get('severities', [])
    if severities:
        command.extend(['-s', ','.join(severities)])

    tags = config.get('tags', [])
    if tags:
        command.extend(['-tags', ','.join(tags)])

    rate_limit = config.get('rate_limit')
    if rate_limit:
        command.extend(['-rl', str(rate_limit)])

    extra_args = config.get('extra_args', '')
    if extra_args:
        command.extend(extra_args.split())

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.jsonl') as tmp_file:
        output_path = tmp_file.name

    command.extend(['-jsonl', '-o', output_path])

    try:
        print(f"  [Nuclei] Running full scan on {target}...", flush=True)
        run_command(command)

        if os.path.exists(output_path):
            with open(output_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        if not line.strip(): continue
                        data = json.loads(line)

                        if 'info' in data:
                            findings.append({
                                'type': data['info'].get('name', 'Unknown Nuclei Finding'),
                                'severity': data['info'].get('severity', 'info').title(),
                                'url': data.get('matched-at', target),
                                'details': {
                                    'template_id': data.get('template-id'),
                                    'description': data['info'].get('description', ''),
                                    'matcher_name': data.get('matcher-name', ''),
                                    'curl_command': data.get('curl-command', ''),
                                    'extracted_results': data.get('extracted-results', [])
                                }
                            })
                    except json.JSONDecodeError:
                        continue
        print(f"  [Nuclei] Scan finished. Found {len(findings)} potential issues.", flush=True)

    except Exception as e:
        print(f"Error running Nuclei: {e}")
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)

    return findings