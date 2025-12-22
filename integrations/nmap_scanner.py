import xml.etree.ElementTree as ET
from .tool_runner import run_command


def _is_nmap_false_positive(script_id: str, output: str) -> bool:
    """
    Checks if the Nmap script output is an error, 'not found' message,
    or just informational banner noise.
    """
    # 1. Phrases indicating NO vulnerability or execution errors
    IGNORE_PHRASES = [
        "Couldn't find any",
        "No vulnerabilities found",
        "0 vulnerabilities found",
        "ERROR: Script execution failed",
        "does not exist",
        "Not vulnerable",
        "State: Clean",
        "use -d to debug",
        "valid credentials",  # Sometimes brute force scripts print 'No valid credentials found'
        "files not found"
    ]

    # 2. Scripts that are informational only (Server Headers, Titles, etc.)
    # These should not be flagged as "Critical Infrastructure Vulnerabilities"
    INFO_ONLY_SCRIPTS = [
        "http-server-header",
        "http-title",
        "http-headers",
        "fingerprint-strings",
        "banner"
    ]

    # Check against ignore phrases
    if any(phrase.lower() in output.lower() for phrase in IGNORE_PHRASES):
        return True

    # Check against info-only script IDs
    if script_id in INFO_ONLY_SCRIPTS:
        return True

    return False


def run_nmap(target: str) -> dict:
    """
    Runs nmap to check ports and run vulnerability scripts.
    Returns a dict with 'ports' and 'vulnerabilities'.
    """
    results = {
        'ports': [],
        'vulnerabilities': []
    }

    # -F: Fast scan
    # -sV: Service version detection
    # -Pn: Treat host as online (skip ping)
    # --script vuln: Run vulnerability detection scripts
    # -oX -: Output XML to stdout
    command = ['nmap', '-F', '-sV', '-Pn', '--script', 'vuln', target, '-oX', '-']

    xml_output = run_command(command)

    if not xml_output:
        return results

    try:
        root = ET.fromstring(xml_output)
        for port in root.findall(".//port"):
            state = port.find("./state").attrib.get('state')
            if state == 'open':
                port_id = port.attrib.get('portid')
                protocol = port.attrib.get('protocol')
                service = port.find("./service")

                service_name = service.attrib.get('name', 'unknown') if service is not None else 'unknown'
                product = service.attrib.get('product', '') if service is not None else ''
                version = service.attrib.get('version', '') if service is not None else ''

                # Add to ports list
                results['ports'].append({
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "product": product,
                    "version": version
                })

                # Process NSE script outputs
                for script in port.findall("./script"):
                    script_id = script.attrib.get('id')
                    output = script.attrib.get('output')

                    # Filter out false positives and noise
                    if not output or _is_nmap_false_positive(script_id, output):
                        continue

                    results['vulnerabilities'].append({
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "script_id": script_id,
                        "output": output
                    })

    except ET.ParseError as e:
        print(f"Error parsing nmap XML output: {e}")

    return results