# integrations/nmap_scanner.py
import xml.etree.ElementTree as ET
from .tool_runner import run_command


def run_nmap(target: str) -> dict:
    results = {
        'ports': [],
        'vulnerabilities': []
    }

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

                results['ports'].append({
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "product": product,
                    "version": version
                })

                for script in port.findall("./script"):
                    script_id = script.attrib.get('id')
                    output = script.attrib.get('output')

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