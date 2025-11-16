# integrations/nmap_scanner.py
import xml.etree.ElementTree as ET
from .tool_runner import run_command


def run_nmap(target: str) -> list:
    findings = []
    # -F: Quét nhanh (100 port phổ biến nhất)
    # -sV: Dò phiên bản dịch vụ
    # -oX -: Output dạng XML ra stdout
    command = ['nmap', '-F', '--script=vuln','-sV', target, '-oX', '-']
    xml_output = run_command(command)

    if not xml_output:
        return findings

    try:
        root = ET.fromstring(xml_output)
        for port in root.findall(".//port"):
            if port.find("./state").attrib.get('state') == 'open':
                service = port.find("./service")
                findings.append({
                    "port": port.attrib.get('portid'),
                    "protocol": port.attrib.get('protocol'),
                    "service_name": service.attrib.get('name', 'unknown'),
                    "product": service.attrib.get('product', ''),
                    "version": service.attrib.get('version', '')
                })
    except ET.ParseError as e:
        print(f"Error parsing nmap XML output: {e}")

    return findings