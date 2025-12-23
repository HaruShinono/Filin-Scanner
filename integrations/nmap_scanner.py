import xml.etree.ElementTree as ET
from .tool_runner import run_command


def _is_nmap_false_positive(script_id: str, output: str) -> bool:
    IGNORE_PHRASES = [
        "Couldn't find any",
        "No vulnerabilities found",
        "0 vulnerabilities found",
        "ERROR: Script execution failed",
        "does not exist",
        "Not vulnerable",
        "State: Clean",
        "use -d to debug",
        "valid credentials",
        "files not found"
    ]

    INFO_ONLY_SCRIPTS = [
        "http-server-header",
        "http-title",
        "http-headers",
        "fingerprint-strings",
        "banner"
    ]

    if any(phrase.lower() in output.lower() for phrase in IGNORE_PHRASES):
        return True

    if script_id in INFO_ONLY_SCRIPTS:
        return True

    return False


def run_nmap(target: str) -> dict:
    results = {
        'ports': [],
        'vulnerabilities': []
    }

    command = ['nmap', '-F', '-sV', '--version-intensity', '5', '-Pn', '--script', 'vuln', target, '-oX', '-']

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
                service_name = 'unknown'
                product = ''
                version = ''
                extrainfo = ''

                if service is not None:
                    service_name = service.attrib.get('name', 'unknown')
                    product = service.attrib.get('product', '')
                    version = service.attrib.get('version', '')
                    extrainfo = service.attrib.get('extrainfo', '')

                full_version_string = f"{product} {version}".strip()
                if extrainfo:
                    full_version_string += f" ({extrainfo})"

                if not full_version_string:
                    full_version_string = service_name

                results['ports'].append({
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "display_string": full_version_string
                })

                for script in port.findall("./script"):
                    script_id = script.attrib.get('id')
                    output = script.attrib.get('output')

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