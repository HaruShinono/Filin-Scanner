import json
import traceback
from datetime import datetime
from urllib.parse import urlparse

from factory import create_app, db
from models import ReconFinding, Scan, Vulnerability
from scanner_core.scanner import Scanner
from scanner_core.scanner import Vulnerability as VulnerabilityDataClass

from integrations.nmap_scanner import run_nmap
from integrations.wafw00f_scanner import run_wafw00f
from integrations.dnsrecon_scanner import run_dnsrecon
from integrations.nuclei_scanner import run_nuclei


def run_scan_task(scan_id: int):
    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            print(f"Error: Scan with ID {scan_id} not found.")
            return

        print(f"Worker started for Scan ID: {scan_id}, Target: {scan.target_url}")
        scan.status = 'RUNNING'
        db.session.commit()

        try:
            # --- PHASE 1: RECONNAISSANCE ---
            print(f"[Scan ID: {scan_id}] Starting reconnaissance phase...")
            parsed_url = urlparse(scan.target_url)
            domain = parsed_url.hostname

            # 1. Run WAFW00F
            waf_result = run_wafw00f(scan.target_url)
            if waf_result:
                finding = ReconFinding(
                    scan_id=scan.id,
                    tool='wafw00f',
                    finding_type='WAF Detected',
                    details=json.dumps(waf_result)
                )
                db.session.add(finding)
                db.session.commit()

            # 2. Run DNSRecon
            if domain:
                dns_results = run_dnsrecon(domain)
                for record in dns_results:
                    rec_type = record.get('type', 'Unknown')
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='dnsrecon',
                        finding_type=f'DNS Record ({rec_type})',
                        details=json.dumps(record)
                    )
                    db.session.add(finding)
                db.session.commit()

            # 3. Run Nmap (Ports and Vulnerabilities)
            if domain:
                nmap_data = run_nmap(domain)

                # Save Open Ports
                for port_info in nmap_data.get('ports', []):
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap',
                        finding_type='Open Port',
                        details=json.dumps(port_info)
                    )
                    db.session.add(finding)

                # Save Nmap Script Vulnerabilities
                for vuln_info in nmap_data.get('vulnerabilities', []):
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap-vuln',
                        finding_type=f"NSE: {vuln_info.get('script_id')}",
                        details=json.dumps(vuln_info)
                    )
                    db.session.add(finding)

                db.session.commit()

            print(f"[Scan ID: {scan_id}] Reconnaissance phase finished.")

            # --- PHASE 2: NUCLEI SCANNING ---
            print(f"[Scan ID: {scan_id}] Running Nuclei scanner...")
            nuclei_results = run_nuclei(scan.target_url)

            for n_vuln in nuclei_results:
                print(f"  [Scan ID: {scan_id}] Nuclei found: {n_vuln['type']}")

                vulnerability_model = Vulnerability(
                    scan_id=scan.id,
                    type=f"[Nuclei] {n_vuln['type']}",
                    subcategory=n_vuln['details'].get('template_id'),
                    url=n_vuln['url'],
                    severity=n_vuln['severity'],
                    details=json.dumps(n_vuln['details'], indent=2)
                )
                db.session.add(vulnerability_model)

            db.session.commit()

            # --- PHASE 3: CORE PYTHON SCANNING ---
            def save_vulnerability_callback(vuln: VulnerabilityDataClass):
                with app.app_context():
                    print(f"  [Scan ID: {scan_id}] Found vulnerability: {vuln.type} at {vuln.url}")
                    vulnerability_model = Vulnerability(
                        scan_id=scan.id,
                        type=vuln.type,
                        subcategory=getattr(vuln, 'subcategory', None),
                        url=vuln.url,
                        severity=vuln.severity,
                        details=json.dumps(vuln.details, indent=2, ensure_ascii=False)
                    )
                    db.session.add(vulnerability_model)
                    db.session.commit()

            # Initialize Scanner with Auth Cookies if available
            scanner_instance = Scanner(
                url=scan.target_url,
                cookies=scan.auth_cookies
            )
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

            scan.status = 'COMPLETED'
            print(f"Scan ID: {scan_id} completed successfully.")

        except Exception as e:
            print(f"Scan ID: {scan_id} for target {scan.target_url} failed.")
            print(f"Error details: {e}")
            traceback.print_exc()

            db.session.rollback()

            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'FAILED'

        finally:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.end_time = datetime.utcnow()
                db.session.commit()
            print(f"Worker finished for Scan ID: {scan_id}")